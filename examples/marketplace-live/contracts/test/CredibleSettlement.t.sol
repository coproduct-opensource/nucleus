// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CredibleSettlement} from "../src/CredibleSettlement.sol";
import {CommitSet} from "../src/CommitSet.sol";

/// Parity + lifecycle tests for the optimistic credible-clearing settlement.
///
/// The `parity_*` tests mirror, vector-for-vector, the Rust parity tests in
/// `crates/nucleus-econ-kernels/src/settlement.rs` and `::commons.rs` (themselves
/// parity-pinned to `SettlementDecision.lean`). They are what BIND the on-chain
/// money path to the Lean proof: if the Solidity diverges from the proven
/// function, these fail.
contract CredibleSettlementTest is Test {
    CredibleSettlement settlement;

    // Mirror of commons.rs `example_splits()`: 60% carbon / 25% affected / 15% commons.
    address constant CARBON = address(0xC0);
    address constant AFFECTED = address(0xA1);
    address constant COMMONS = address(0xC5);

    address constant BUYER = address(0xB0);
    address constant SELLER = address(0x5E);
    address constant ARBITER = address(0xA2);
    address constant POSTER = address(0x90);
    address constant WATCHER = address(0x77);

    function setUp() public {
        address[] memory dests = new address[](3);
        dests[0] = CARBON;
        dests[1] = AFFECTED;
        dests[2] = COMMONS;
        uint64[] memory bps = new uint64[](3);
        bps[0] = 6_000;
        bps[1] = 2_500;
        bps[2] = 1_500;
        settlement = new CredibleSettlement(dests, bps);
    }

    // ── Parity: classify (settlement.rs::classify_matches_lean_total) ──────────

    function test_parity_classify() public view {
        assertEq(uint8(settlement.classify(0)), uint8(CredibleSettlement.Verdict.Reverse));
        assertEq(uint8(settlement.classify(1)), uint8(CredibleSettlement.Verdict.Partial));
        assertEq(uint8(settlement.classify(9_999)), uint8(CredibleSettlement.Verdict.Partial));
        assertEq(uint8(settlement.classify(10_000)), uint8(CredibleSettlement.Verdict.Release));
        assertEq(uint8(settlement.classify(50_000)), uint8(CredibleSettlement.Verdict.Release));
    }

    // ── Parity: release/reverse extremes (release_is_full_payout_reverse…) ─────

    function test_parity_release_and_reverse_extremes() public view {
        assertEq(settlement.sellerGross(1_000_000, 10_000), 1_000_000);
        assertEq(settlement.refund(1_000_000, 10_000), 0);
        assertEq(settlement.sellerGross(1_000_000, 0), 0);
        assertEq(settlement.refund(1_000_000, 0), 1_000_000);
    }

    // ── Parity: conservation battery (conservation_holds_for_a_battery_of_inputs) ─

    function test_parity_conservation_battery() public view {
        uint256[6] memory prices =
            [uint256(0), 1, 999, 1_000_000, 7_654_321, uint256(type(uint64).max) / 2];
        uint64[7] memory bpsCases = [uint64(0), 1, 2_500, 5_000, 9_999, 10_000, 25_000];
        for (uint256 i = 0; i < prices.length; i++) {
            for (uint256 j = 0; j < bpsCases.length; j++) {
                uint256 g = settlement.sellerGross(prices[i], bpsCases[j]);
                uint256 r = settlement.refund(prices[i], bpsCases[j]);
                assertEq(g + r, prices[i], "conservation violated");
                assertLe(g, prices[i], "sellerGross <= price");
            }
        }
    }

    // ── Parity: monotone gross / antitone refund (seller_gross_monotone…) ──────

    function test_parity_monotone_gross_antitone_refund() public view {
        uint256 price = 1_000_000;
        uint64[5] memory bpsCases = [uint64(0), 1_000, 5_000, 9_000, 10_000];
        uint256 lastGross;
        uint256 lastRefund = price;
        for (uint256 i = 0; i < bpsCases.length; i++) {
            uint256 g = settlement.sellerGross(price, bpsCases[i]);
            uint256 r = settlement.refund(price, bpsCases[i]);
            assertGe(g, lastGross, "gross must be monotone");
            assertLe(r, lastRefund, "refund must be antitone");
            lastGross = g;
            lastRefund = r;
        }
    }

    // ── Parity: commons routing (commons.rs::proportional_split + conservation) ─

    function test_parity_commons_proportional_and_dust() public view {
        uint256[] memory a = settlement.routeToCommons(1_000_000);
        assertEq(a[0], 600_000); // 60%
        assertEq(a[1], 250_000); // 25%
        assertEq(a[2], 150_000); // 15%

        // Dusty pool=7: 4/1/1 = 6, dust 1 → first = 5 (matches the Rust test).
        uint256[] memory d = settlement.routeToCommons(7);
        assertEq(d[0], 5);
        assertEq(d[1], 1);
        assertEq(d[2], 1);
        assertEq(d[0] + d[1] + d[2], 7, "commons no-skim");
    }

    function test_parity_commons_no_skim_battery() public view {
        uint256[5] memory pools = [uint256(0), 1, 7, 1_000_000, 9_999_999];
        for (uint256 i = 0; i < pools.length; i++) {
            uint256[] memory a = settlement.routeToCommons(pools[i]);
            assertEq(a[0] + a[1] + a[2], pools[i], "skim/loss");
        }
    }

    function test_constructor_rejects_bad_shares() public {
        address[] memory dests = new address[](2);
        dests[0] = CARBON;
        dests[1] = AFFECTED;
        uint64[] memory bps = new uint64[](2);
        bps[0] = 5_000;
        bps[1] = 4_000; // sums to 9_000
        vm.expectRevert(abi.encodeWithSelector(CredibleSettlement.BadCommonsShares.selector, uint64(9_000)));
        new CredibleSettlement(dests, bps);
    }

    // ── Lifecycle: happy path (release) self-executes the proven split ─────────

    // The canonical sealed-bid commitment set, strictly ascending (as CommitSet
    // requires). _open anchors CommitSet.root(_bids()); _post reveals _bids().
    function _bids() internal pure returns (bytes32[] memory s) {
        s = new bytes32[](3);
        s[0] = bytes32(uint256(0x11));
        s[1] = bytes32(uint256(0x22));
        s[2] = bytes32(uint256(0x33));
    }

    function _open(bytes32 id, uint256 price) internal {
        vm.deal(BUYER, price);
        vm.prank(BUYER);
        settlement.openRound{value: price}(
            id, SELLER, ARBITER, CommitSet.root(_bids()), uint64(block.timestamp + 100)
        );
    }

    function _post(bytes32 id, uint256 bond, uint256 priceMicro) internal {
        vm.warp(block.timestamp + 101); // past reveal deadline
        vm.deal(POSTER, bond);
        vm.prank(POSTER);
        settlement.postClearing{value: bond}(id, _bids(), priceMicro, 50);
    }

    function test_lifecycle_release_pays_seller_in_full() public {
        bytes32 id = keccak256("r1");
        uint256 price = 1 ether;
        _open(id, price);
        _post(id, 0.1 ether, 1_000_000);
        vm.warp(block.timestamp + 51); // past challenge window

        vm.prank(ARBITER);
        settlement.settle(id, 10_000); // fully delivered

        assertEq(SELLER.balance, price, "seller paid full price");
        assertEq(POSTER.balance, 0.1 ether, "honest poster reclaims bond");
        assertEq(uint8(settlement.phaseOf(id)), uint8(CredibleSettlement.Phase.Settled));
    }

    function test_lifecycle_partial_splits_seller_and_buyer() public {
        bytes32 id = keccak256("r2");
        uint256 price = 1 ether;
        _open(id, price);
        _post(id, 0.1 ether, 1_000_000);
        vm.warp(block.timestamp + 51);

        vm.prank(ARBITER);
        settlement.settle(id, 2_500); // 25% delivered

        assertEq(SELLER.balance, price / 4, "seller gets 25%");
        assertEq(BUYER.balance, price - price / 4, "buyer refunded 75%");
    }

    function test_lifecycle_reverse_refunds_buyer_fully() public {
        bytes32 id = keccak256("r3");
        uint256 price = 1 ether;
        _open(id, price);
        _post(id, 0.1 ether, 1_000_000);
        vm.warp(block.timestamp + 51);

        vm.prank(ARBITER);
        settlement.settle(id, 0); // nothing delivered

        assertEq(BUYER.balance, price, "buyer fully refunded");
        assertEq(SELLER.balance, 0, "seller gets nothing");
    }

    // ── Lifecycle: challenge slashes bond to commons + reverses ────────────────

    function test_challenge_slashes_bond_to_commons_and_refunds_buyer() public {
        bytes32 id = keccak256("r4");
        uint256 price = 1 ether;
        uint256 bond = 0.1 ether;
        _open(id, price);
        _post(id, bond, 1_000_000);

        vm.prank(WATCHER);
        settlement.challenge(id); // within window

        // Buyer refunded the full escrowed price.
        assertEq(BUYER.balance, price, "buyer refunded on reversal");
        // Bond routed to commons 60/25/15 with no skim.
        assertEq(CARBON.balance, (bond * 6_000) / 10_000);
        assertEq(AFFECTED.balance, (bond * 2_500) / 10_000);
        assertEq(COMMONS.balance, (bond * 1_500) / 10_000);
        assertEq(CARBON.balance + AFFECTED.balance + COMMONS.balance, bond, "commons no-skim");
        assertEq(uint8(settlement.phaseOf(id)), uint8(CredibleSettlement.Phase.Reversed));
    }

    function test_challenge_after_window_reverts() public {
        bytes32 id = keccak256("r5");
        _open(id, 1 ether);
        _post(id, 0.1 ether, 1_000_000);
        vm.warp(block.timestamp + 51); // window closed
        vm.expectRevert(CredibleSettlement.ChallengeWindowClosed.selector);
        vm.prank(WATCHER);
        settlement.challenge(id);
    }

    function test_settle_before_window_closes_reverts() public {
        bytes32 id = keccak256("r6");
        _open(id, 1 ether);
        _post(id, 0.1 ether, 1_000_000);
        vm.expectRevert(CredibleSettlement.ChallengeWindowOpen.selector);
        vm.prank(ARBITER);
        settlement.settle(id, 10_000);
    }

    function test_settle_only_by_arbiter() public {
        bytes32 id = keccak256("r7");
        _open(id, 1 ether);
        _post(id, 0.1 ether, 1_000_000);
        vm.warp(block.timestamp + 51);
        vm.expectRevert(CredibleSettlement.NotArbiter.selector);
        vm.prank(WATCHER);
        settlement.settle(id, 10_000);
    }

    function test_post_before_reveal_reverts() public {
        bytes32 id = keccak256("r8");
        _open(id, 1 ether);
        vm.deal(POSTER, 0.1 ether);
        vm.expectRevert(CredibleSettlement.RevealNotReached.selector);
        vm.prank(POSTER);
        settlement.postClearing{value: 0.1 ether}(id, _bids(), 1_000_000, 50);
    }

    // ── G5: on-chain completeness — OMIT / FABRICATE / tamper each caught ──────

    // The honest, complete set posts fine (and the lifecycle tests above all post
    // via _post(_bids()), so the happy path is covered). These assert each way of
    // corrupting the revealed set is rejected by the anchored commitmentSetRoot.

    function _postSet(bytes32 id, bytes32[] memory set) internal {
        vm.warp(block.timestamp + 101); // past reveal deadline
        vm.deal(POSTER, 0.1 ether);
        vm.prank(POSTER);
        settlement.postClearing{value: 0.1 ether}(id, set, 1_000_000, 50);
    }

    function test_post_omit_bid_reverts() public {
        bytes32 id = keccak256("g5-omit");
        _open(id, 1 ether);
        // Drop the last committed bid (suppress competition). Root no longer matches.
        bytes32[] memory omitted = new bytes32[](2);
        omitted[0] = bytes32(uint256(0x11));
        omitted[1] = bytes32(uint256(0x22));
        vm.expectRevert(CredibleSettlement.CommitmentSetMismatch.selector);
        _postSet(id, omitted);
    }

    function test_post_fabricate_bid_reverts() public {
        bytes32 id = keccak256("g5-fab");
        _open(id, 1 ether);
        // Inject a bid that was never committed (inflate the price). Root mismatch.
        bytes32[] memory fabricated = new bytes32[](4);
        fabricated[0] = bytes32(uint256(0x11));
        fabricated[1] = bytes32(uint256(0x22));
        fabricated[2] = bytes32(uint256(0x33));
        fabricated[3] = bytes32(uint256(0x44));
        vm.expectRevert(CredibleSettlement.CommitmentSetMismatch.selector);
        _postSet(id, fabricated);
    }

    function test_post_altered_bid_reverts() public {
        bytes32 id = keccak256("g5-alter");
        _open(id, 1 ether);
        // Swap one commitment for a different value (same count). Root mismatch.
        bytes32[] memory altered = new bytes32[](3);
        altered[0] = bytes32(uint256(0x11));
        altered[1] = bytes32(uint256(0x22));
        altered[2] = bytes32(uint256(0x99));
        vm.expectRevert(CredibleSettlement.CommitmentSetMismatch.selector);
        _postSet(id, altered);
    }

    function test_post_unsorted_set_reverts() public {
        bytes32 id = keccak256("g5-unsorted");
        _open(id, 1 ether);
        // Correct members, non-canonical (descending) order → CommitSet rejects.
        bytes32[] memory unsorted = new bytes32[](3);
        unsorted[0] = bytes32(uint256(0x33));
        unsorted[1] = bytes32(uint256(0x22));
        unsorted[2] = bytes32(uint256(0x11));
        vm.expectRevert(CommitSet.UnsortedOrDuplicate.selector);
        _postSet(id, unsorted);
    }

    function test_post_duplicate_in_set_reverts() public {
        bytes32 id = keccak256("g5-dup");
        _open(id, 1 ether);
        bytes32[] memory dup = new bytes32[](3);
        dup[0] = bytes32(uint256(0x11));
        dup[1] = bytes32(uint256(0x11)); // duplicate (not strictly ascending)
        dup[2] = bytes32(uint256(0x33));
        vm.expectRevert(CommitSet.UnsortedOrDuplicate.selector);
        _postSet(id, dup);
    }

    function test_post_complete_set_succeeds_then_settles() public {
        // The full, canonical set posts, and the round settles normally — proving
        // the completeness gate is not over-strict (MISPRICE is the only remaining
        // seam, handled optimistically by challenge()).
        bytes32 id = keccak256("g5-ok");
        _open(id, 1 ether);
        _postSet(id, _bids());
        assertEq(uint8(settlement.phaseOf(id)), uint8(CredibleSettlement.Phase.Posted));
        vm.warp(block.timestamp + 51);
        vm.prank(ARBITER);
        settlement.settle(id, 10_000);
        assertEq(SELLER.balance, 1 ether, "complete honest set settles in full");
    }

    // Fuzz: conservation must hold on-chain for arbitrary price × delivery.
    function testFuzz_conservation(uint128 price, uint64 bps) public view {
        uint256 g = settlement.sellerGross(price, bps);
        uint256 r = settlement.refund(price, bps);
        assertEq(g + r, uint256(price));
        assertLe(g, uint256(price));
    }

    // Fuzz: commons routing never skims or over-allocates.
    function testFuzz_commons_no_skim(uint128 pool) public view {
        uint256[] memory a = settlement.routeToCommons(pool);
        assertEq(a[0] + a[1] + a[2], uint256(pool));
    }
}
