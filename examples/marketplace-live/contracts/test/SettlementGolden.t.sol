// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {CredibleSettlement} from "../src/CredibleSettlement.sol";

/// The Solidity arm of the cross-language golden seal (gap G3).
///
/// Reads the SAME single-source vectors that pin the Lean (`Nucleus/Golden.lean`),
/// Rust (`tests/golden.rs`), and WASM (`test/golden.test.mjs`) readers —
/// `crates/nucleus-econ-kernels/tests/golden/settlement.json` — via `vm.readFile`
/// and asserts the on-chain `CredibleSettlement.classify / sellerGross / refund`
/// reproduce every vector. If the Solidity money path ever diverges from the
/// proven settlement function, this turns CI red — the JSON is the one source all
/// four implementations must agree with.
///
/// The golden file lives OUTSIDE the Foundry root; `foundry.toml` grants read
/// access to that directory.
contract SettlementGoldenTest is Test {
    using stdJson for string;

    CredibleSettlement settlement;

    // Mirror of commons.rs example_splits (unused here but required by the ctor).
    function setUp() public {
        address[] memory dests = new address[](3);
        dests[0] = address(0xC0);
        dests[1] = address(0xA1);
        dests[2] = address(0xC5);
        uint64[] memory bps = new uint64[](3);
        bps[0] = 6_000;
        bps[1] = 2_500;
        bps[2] = 1_500;
        settlement = new CredibleSettlement(dests, bps);
    }

    /// One golden settlement vector. Field order is ALPHABETICAL — forge decodes
    /// JSON objects into structs by sorted key name, not declaration order.
    struct Vector {
        uint256 delivered_bps;
        uint256 price_micro;
        uint256 refund;
        uint256 seller_gross;
        uint256 verdict; // 0 = reverse, 1 = partial, 2 = release
    }

    function test_settlement_matches_golden_vectors() public view {
        string memory path = string.concat(
            vm.projectRoot(), "/../../../crates/nucleus-econ-kernels/tests/golden/settlement.json"
        );
        string memory json = vm.readFile(path);

        Vector[] memory vectors = abi.decode(json.parseRaw(".vectors"), (Vector[]));
        assertGt(vectors.length, 0, "golden file has no vectors");

        for (uint256 i = 0; i < vectors.length; i++) {
            Vector memory v = vectors[i];
            uint64 price = uint64(v.price_micro);
            uint64 bps = uint64(v.delivered_bps);

            assertEq(
                uint8(settlement.classify(bps)),
                uint8(v.verdict),
                "classify diverges from golden"
            );
            assertEq(
                settlement.sellerGross(price, bps),
                v.seller_gross,
                "sellerGross diverges from golden"
            );
            assertEq(settlement.refund(price, bps), v.refund, "refund diverges from golden");
            // Conservation (the Lean theorem) on the Solidity path too.
            assertEq(
                settlement.sellerGross(price, bps) + settlement.refund(price, bps),
                price,
                "conservation violated"
            );
        }
    }
}
