// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../chain/contracts/TrustGraph.sol";

contract BatchLimitTest is Test {
    TrustGraph private trustGraph;

    address private constant ADMIN = address(0xA11CE);
    address private constant AUTHORIZED_EVALUATOR = address(0xE1);

    bytes32 private constant EVALUATOR_ID = keccak256("evaluator-1");
    bytes32 private constant ENTITY_ID_A = keccak256("entity-a");
    bytes32 private constant ENTITY_ID_B = keccak256("entity-b");

    function setUp() public {
        vm.prank(ADMIN);
        trustGraph = new TrustGraph();

        vm.prank(ADMIN);
        trustGraph.updateEvaluator(AUTHORIZED_EVALUATOR, true);
    }

    function testAdminCanUpdateBatchLimitAndPublishWithinLimit() public {
        vm.prank(ADMIN);
        trustGraph.setBatchLimit(2);

        assertEq(trustGraph.getBatchLimit(), 2, "batch limit must track admin configuration");

        bytes32[] memory evaluators = new bytes32[](2);
        evaluators[0] = EVALUATOR_ID;
        evaluators[1] = EVALUATOR_ID;

        bytes32[] memory entities = new bytes32[](2);
        entities[0] = ENTITY_ID_A;
        entities[1] = ENTITY_ID_B;

        bool[] memory decisions = new bool[](2);
        decisions[0] = true;
        decisions[1] = false;

        vm.prank(AUTHORIZED_EVALUATOR);
        trustGraph.batchSetTrustDecisions(evaluators, entities, decisions);

        assertTrue(
            trustGraph.getTrustDecision(EVALUATOR_ID, ENTITY_ID_A),
            "first decision should be recorded when within limit"
        );
        assertFalse(
            trustGraph.getTrustDecision(EVALUATOR_ID, ENTITY_ID_B),
            "second decision should match submitted payload"
        );
    }

    function testBatchAboveLimitReverts() public {
        vm.prank(ADMIN);
        trustGraph.setBatchLimit(1);

        bytes32[] memory evaluators = new bytes32[](2);
        evaluators[0] = EVALUATOR_ID;
        evaluators[1] = EVALUATOR_ID;

        bytes32[] memory entities = new bytes32[](2);
        entities[0] = ENTITY_ID_A;
        entities[1] = ENTITY_ID_B;

        bool[] memory decisions = new bool[](2);
        decisions[0] = true;
        decisions[1] = true;

        vm.expectRevert(abi.encodeWithSelector(TrustGraph.BatchLimitExceeded.selector, 2, 1));
        vm.prank(AUTHORIZED_EVALUATOR);
        trustGraph.batchSetTrustDecisions(evaluators, entities, decisions);
    }

    function testNonAdminCannotUpdateBatchLimit() public {
        vm.expectRevert(abi.encodeWithSelector(TrustGraph.NotAdmin.selector, AUTHORIZED_EVALUATOR));
        vm.prank(AUTHORIZED_EVALUATOR);
        trustGraph.setBatchLimit(2);
    }

    function testZeroBatchLimitRejected() public {
        vm.expectRevert(TrustGraph.InvalidBatchLimit.selector);
        vm.prank(ADMIN);
        trustGraph.setBatchLimit(0);
    }
}
