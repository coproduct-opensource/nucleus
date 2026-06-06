// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CommitSet} from "./CommitSet.sol";

/// @title CredibleSettlement — optimistic credible-clearing settlement (Bet B, B2)
/// @notice Removes the *trusted auctioneer* from an off-chain VCG/Pigou auction:
/// the verified settlement **self-executes on-chain** so no one must be trusted to
/// *act* on the outcome. Base Sepolia testnet only.
///
/// ## What is proven on-chain (the trustless core)
/// The settlement split — `classify` / `sellerGross` / `refund` — is a byte-for-
/// byte mirror of `nucleus-econ-kernels::settlement` (itself parity-pinned to
/// `lean/Nucleus/Auctions/SettlementDecision.lean`). The load-bearing invariant
/// `sellerGross + refund == price` holds by construction (`refund` is the
/// residual) and is re-checked by the Foundry parity test against the SAME vectors
/// the Rust test uses. The commons routing (`routeToCommons`) likewise mirrors
/// `nucleus-econ-kernels::commons` with no-skim conservation. So the money path
/// runs the EXACT proven functions — not an approximation of them.
///
/// ## What is optimistic (the documented seam)
/// The *cleared price* itself is posted optimistically: the contract does NOT run
/// VCG on-chain (too expensive). Instead the poster bonds the claim, and during a
/// challenge window any watcher who runs the coproduct/verify SDK's recompute off-chain
/// and finds `claimed != recompute` can `challenge()` → the poster's bond is
/// slashed to the commons and the round safely **reverses** (buyer refunded). This
/// makes cheating unprofitable and gives a safe fallback WITHOUT on-chain
/// adjudication. Deciding *who is right* between poster and challenger (vs. always
/// reversing) needs interactive fraud proofs / on-chain commit — that is B3, and
/// is intentionally NOT claimed here.
///
/// ## What is NOT solved
/// `deliveredBps` (did the seller actually deliver?) is an INPUT supplied by the
/// round's `arbiter` — the Proof-of-Task-Execution (PoTE) seam, the one unsolved
/// part of Bet B. The proof says nothing about whether delivery truly occurred.
/// See `docs/rfcs/credible-clearing-settlement.md`.
contract CredibleSettlement {
    // ── Proven constants (mirror Lean `bpsScale` / Rust `BPS_SCALE`) ────────
    uint64 internal constant BPS_SCALE = 10_000;

    enum Verdict {
        Reverse, // deliveredBps == 0
        Partial, // 0 < deliveredBps < 10_000
        Release // deliveredBps >= 10_000
    }

    enum Phase {
        None,
        Open, // funds escrowed, awaiting reveal + post
        Posted, // clearing posted + bonded, challenge window open
        Settled, // split executed to seller + buyer
        Reversed // challenged or arbiter-reversed: buyer fully refunded
    }

    struct Round {
        address buyer; // escrowed the cleared price
        address seller; // paid `sellerGross` on delivery
        address arbiter; // supplies `deliveredBps` (the PoTE oracle seam)
        uint256 price; // escrowed cleared price (native wei, testnet)
        bytes32 commitmentSetRoot; // anchored sealed-bid set; ENFORCED at postClearing (G5)
        uint64 revealDeadline; // bids open (off-chain drand timelock) after this
        address poster; // posted the optimistic clearing claim
        uint256 bond; // poster's bond, slashed to commons on a valid challenge
        bytes32 revealedBidsHash; // hash of the revealed bids the poster claims
        uint256 clearedPriceMicro; // claimed cleared price (audit; must == price)
        uint64 challengeDeadline; // settle allowed only after this, if unchallenged
        Phase phase;
    }

    // Immutable commons split (set at construction; sum MUST be 10_000 bps).
    address[] public commonsDestinations;
    uint64[] public commonsBps;

    mapping(bytes32 => Round) private _rounds;

    event RoundOpened(
        bytes32 indexed roundId,
        address indexed buyer,
        address indexed seller,
        uint256 price,
        bytes32 commitmentSetRoot,
        uint64 revealDeadline
    );
    event ClearingPosted(
        bytes32 indexed roundId,
        address indexed poster,
        bytes32 revealedBidsHash,
        uint256 clearedPriceMicro,
        uint256 bond,
        uint64 challengeDeadline
    );
    event Challenged(bytes32 indexed roundId, address indexed challenger, uint256 slashedToCommons);
    event Settled(
        bytes32 indexed roundId, Verdict verdict, uint64 deliveredBps, uint256 sellerGrossPaid, uint256 refundPaid
    );
    event CommonsAllocated(bytes32 indexed roundId, address indexed destination, uint256 amount);

    error BadCommonsShares(uint64 sumBps);
    error WrongPhase();
    error NotArbiter();
    error RevealNotReached();
    error ChallengeWindowOpen();
    error ChallengeWindowClosed();
    error ZeroPrice();
    error InsufficientBond();
    error TransferFailed();
    /// The revealed commitment set does not reproduce the `commitmentSetRoot`
    /// anchored at `openRound` — an OMITted, FABRICATEd, or altered bid (G5).
    error CommitmentSetMismatch();

    /// @param destinations commons payout addresses (carbon removal, affected-party, verifier commons, …)
    /// @param bps          their basis-point shares; MUST sum to exactly 10_000
    constructor(address[] memory destinations, uint64[] memory bps) {
        if (destinations.length == 0 || destinations.length != bps.length) {
            revert BadCommonsShares(0);
        }
        uint64 sum;
        for (uint256 i = 0; i < bps.length; i++) {
            sum += bps[i];
        }
        if (sum != BPS_SCALE) revert BadCommonsShares(sum);
        commonsDestinations = destinations;
        commonsBps = bps;
    }

    // ── Proven decision core (mirror of settlement.rs / SettlementDecision.lean) ──

    /// Mirror of Rust `classify` / Lean `classify`.
    function classify(uint64 deliveredBps) public pure returns (Verdict) {
        if (deliveredBps == 0) return Verdict.Reverse;
        if (deliveredBps < BPS_SCALE) return Verdict.Partial;
        return Verdict.Release;
    }

    /// Mirror of Rust `seller_gross` / Lean `sellerGross`: `price * min(bps,10000) / 10000`.
    /// Solidity `uint256` arithmetic gives the same value as the Rust `u128` intermediate.
    function sellerGross(uint256 priceMicro, uint64 deliveredBps) public pure returns (uint256) {
        uint256 bps = deliveredBps < BPS_SCALE ? deliveredBps : BPS_SCALE;
        return (priceMicro * bps) / BPS_SCALE;
    }

    /// Mirror of Rust `refund` / Lean: the residual, so `sellerGross + refund == price` exactly.
    function refund(uint256 priceMicro, uint64 deliveredBps) public pure returns (uint256) {
        return priceMicro - sellerGross(priceMicro, deliveredBps);
    }

    /// Mirror of Rust `route_to_commons` / `nucleus-econ-kernels::commons`: proportional
    /// split with integer-division dust assigned to the FIRST destination, so the
    /// allocations sum to EXACTLY `pool` (no skim). Pure/auditable.
    function routeToCommons(uint256 pool) public view returns (uint256[] memory amounts) {
        uint256 n = commonsBps.length;
        amounts = new uint256[](n);
        uint256 allocated;
        for (uint256 i = 0; i < n; i++) {
            amounts[i] = (pool * commonsBps[i]) / BPS_SCALE;
            allocated += amounts[i];
        }
        amounts[0] += pool - allocated; // dust → first (Σ == pool)
    }

    // ── Optimistic settlement lifecycle ────────────────────────────────────

    /// Buyer opens a round and escrows the cleared price (`msg.value`).
    function openRound(
        bytes32 roundId,
        address seller,
        address arbiter,
        bytes32 commitmentSetRoot,
        uint64 revealDeadline
    ) external payable {
        if (_rounds[roundId].phase != Phase.None) revert WrongPhase();
        if (msg.value == 0) revert ZeroPrice();
        _rounds[roundId] = Round({
            buyer: msg.sender,
            seller: seller,
            arbiter: arbiter,
            price: msg.value,
            commitmentSetRoot: commitmentSetRoot,
            revealDeadline: revealDeadline,
            poster: address(0),
            bond: 0,
            revealedBidsHash: bytes32(0),
            clearedPriceMicro: 0,
            challengeDeadline: 0,
            phase: Phase.Open
        });
        emit RoundOpened(roundId, msg.sender, seller, msg.value, commitmentSetRoot, revealDeadline);
    }

    /// Anyone (an untrusted "sequencer") posts the revealed bid commitments +
    /// claimed clearing, bonding `msg.value`. Allowed only after the reveal
    /// deadline. Opens a challenge window of `challengeWindowSecs`.
    ///
    /// COMPLETENESS (gap G5): `revealedCommitments` must be the FULL sealed-bid
    /// set, in strictly-ascending order. The contract recomputes
    /// `CommitSet.root(revealedCommitments)` and requires it to equal the
    /// `commitmentSetRoot` anchored at `openRound` — so a poster cannot OMIT a
    /// committed bid (to suppress competition) or FABRICATE one (to inflate the
    /// price): either changes the root and reverts here. This is the on-chain
    /// half; the off-chain SDK runs the SAME fold to detect it before posting.
    /// The cleared *price* stays optimistic (bond + challenge) — see `challenge`.
    function postClearing(
        bytes32 roundId,
        bytes32[] calldata revealedCommitments,
        uint256 clearedPriceMicro,
        uint64 challengeWindowSecs
    ) external payable {
        Round storage r = _rounds[roundId];
        if (r.phase != Phase.Open) revert WrongPhase();
        if (block.timestamp < r.revealDeadline) revert RevealNotReached();
        if (msg.value == 0) revert InsufficientBond();
        // OMIT / FABRICATE / tamper closure: the revealed set must reproduce the
        // anchored root exactly.
        bytes32 setRoot = CommitSet.root(revealedCommitments);
        if (setRoot != r.commitmentSetRoot) revert CommitmentSetMismatch();
        r.poster = msg.sender;
        r.bond = msg.value;
        r.revealedBidsHash = setRoot;
        r.clearedPriceMicro = clearedPriceMicro;
        r.challengeDeadline = uint64(block.timestamp) + challengeWindowSecs;
        r.phase = Phase.Posted;
        emit ClearingPosted(roundId, msg.sender, setRoot, clearedPriceMicro, msg.value, r.challengeDeadline);
    }

    /// A watcher who ran the off-chain recompute and found the posted clearing
    /// wrong challenges within the window: the poster's bond is routed to the
    /// commons (anti-grief, non-extractive) and the round safely REVERSES — the
    /// buyer is fully refunded. (Adjudicating poster-vs-challenger instead of
    /// always reversing is B3; not claimed here.)
    function challenge(bytes32 roundId) external {
        Round storage r = _rounds[roundId];
        if (r.phase != Phase.Posted) revert WrongPhase();
        if (block.timestamp >= r.challengeDeadline) revert ChallengeWindowClosed();
        uint256 slashed = r.bond;
        r.bond = 0;
        r.phase = Phase.Reversed;
        // Slashed bond → commons; buyer refunded the full escrowed price.
        _payCommons(roundId, slashed);
        _send(r.buyer, r.price);
        emit Challenged(roundId, msg.sender, slashed);
    }

    /// After an unchallenged window, the arbiter supplies `deliveredBps` (the PoTE
    /// seam) and the contract executes the PROVEN split on-chain: `sellerGross` to
    /// the seller, `refund` to the buyer, and returns the poster's bond. The split
    /// runs the exact mirrored functions — conservation (`sellerGross + refund ==
    /// price`) holds by construction.
    function settle(bytes32 roundId, uint64 deliveredBps) external {
        Round storage r = _rounds[roundId];
        if (r.phase != Phase.Posted) revert WrongPhase();
        if (block.timestamp < r.challengeDeadline) revert ChallengeWindowOpen();
        if (msg.sender != r.arbiter) revert NotArbiter();

        Verdict v = classify(deliveredBps);
        uint256 toSeller = sellerGross(r.price, deliveredBps);
        uint256 toBuyer = refund(r.price, deliveredBps);
        uint256 bond = r.bond;
        r.bond = 0;
        r.phase = Phase.Settled;

        if (toSeller > 0) _send(r.seller, toSeller);
        if (toBuyer > 0) _send(r.buyer, toBuyer);
        if (bond > 0) _send(r.poster, bond); // honest poster reclaims bond

        emit Settled(roundId, v, deliveredBps, toSeller, toBuyer);
    }

    // ── Views ───────────────────────────────────────────────────────────────

    function phaseOf(bytes32 roundId) external view returns (Phase) {
        return _rounds[roundId].phase;
    }

    function roundOf(bytes32 roundId) external view returns (Round memory) {
        return _rounds[roundId];
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    function _payCommons(bytes32 roundId, uint256 pool) internal {
        if (pool == 0) return;
        uint256[] memory amounts = routeToCommons(pool);
        for (uint256 i = 0; i < amounts.length; i++) {
            if (amounts[i] > 0) {
                _send(commonsDestinations[i], amounts[i]);
                emit CommonsAllocated(roundId, commonsDestinations[i], amounts[i]);
            }
        }
    }

    function _send(address to, uint256 amount) internal {
        (bool ok,) = payable(to).call{value: amount}("");
        if (!ok) revert TransferFailed();
    }
}
