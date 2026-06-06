// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CommitSet — canonical set-commitment over sealed-bid commitments (gap G5).
/// @notice Deterministic root of a SET of bid-commitment hashes, used to anchor
/// auction *completeness* on-chain. The root is an ordered keccak fold over the
/// commitments in STRICTLY ASCENDING order, so it is:
///
///   - independent of the order bids were submitted (the poster sorts before
///     posting — the canonical order is the value order, not arrival order), yet
///   - sensitive to ANY change to the set: adding a commitment (FABRICATE),
///     dropping one (OMIT), or altering one all change the root.
///
/// Requiring strictly-ascending leaves makes the root canonical for a given set
/// and rejects duplicate commitments for free. The off-chain coproduct/verify SDK
/// mirrors this construction byte-for-byte: `fold keccak256(acc, leaf)` from
/// `bytes32(0)` over the ascending commitments.
///
/// This is what closes the OMIT/FABRICATE seam: `CredibleSettlement.postClearing`
/// recomputes this root over the revealed commitments and requires it to equal the
/// `commitmentSetRoot` anchored at `openRound`. The complementary MISPRICE seam
/// (cleared price ≠ recompute) stays optimistic — VCG is too expensive on-chain —
/// and is handled by the bond + challenge path.
library CommitSet {
    /// Leaves were not in strictly-ascending order (non-canonical, or a duplicate /
    /// zero commitment).
    error UnsortedOrDuplicate();

    /// Canonical root of the commitment set: `keccak256(acc, leaf)` folded from
    /// `bytes32(0)` over `leaves` in strictly-ascending order. The empty set has
    /// root `bytes32(0)`. Reverts if `leaves` is not strictly ascending (which also
    /// forbids a zero leaf and any duplicate).
    function root(bytes32[] memory leaves) internal pure returns (bytes32 acc) {
        bytes32 prev = bytes32(0);
        acc = bytes32(0);
        for (uint256 i = 0; i < leaves.length; i++) {
            // Strictly ascending vs. the running max (which starts at 0) → canonical
            // order, no duplicates, no zero leaf.
            if (uint256(leaves[i]) <= uint256(prev)) revert UnsortedOrDuplicate();
            prev = leaves[i];
            acc = keccak256(abi.encodePacked(acc, leaves[i]));
        }
    }
}
