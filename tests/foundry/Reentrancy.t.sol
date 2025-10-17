// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../chain/contracts/TrustGraph.sol";

contract TrustGraphHarness is TrustGraph {
    bool private reenterOnSet;

    function configureReenterOnSet(bool enabled) external onlyAdmin {
        reenterOnSet = enabled;
    }

    function _beforeSetTrustDecision(bytes32 evaluator, bytes32 entity, bool trusted) internal override {
        if (reenterOnSet) {
            this.setTrustDecision(evaluator, entity, trusted);
        }
    }
}

contract ReentrancyTest is Test {
    TrustGraphHarness private trustGraph;

    address private constant ADMIN = address(0xA11CE);
    address private constant AUTHORIZED_EVALUATOR = address(0xE1);

    bytes32 private constant EVALUATOR_ID = keccak256("evaluator-1");
    bytes32 private constant ENTITY_ID = keccak256("entity-1");

    function setUp() public {
        vm.prank(ADMIN);
        trustGraph = new TrustGraphHarness();

        vm.prank(ADMIN);
        trustGraph.updateEvaluator(AUTHORIZED_EVALUATOR, true);

        vm.prank(ADMIN);
        trustGraph.updateEvaluator(address(trustGraph), true);
    }

    function testReentrantSetTrustDecisionFails() public {
        vm.prank(ADMIN);
        trustGraph.configureReenterOnSet(true);

        vm.expectRevert(TrustGraph.ReentrantCall.selector);
        vm.prank(AUTHORIZED_EVALUATOR);
        trustGraph.setTrustDecision(EVALUATOR_ID, ENTITY_ID, true);
    }

    function testBatchLengthMismatchDoesNotMutateState() public {
        vm.prank(AUTHORIZED_EVALUATOR);
        trustGraph.setTrustDecision(EVALUATOR_ID, ENTITY_ID, true);

        bytes32[] memory evaluatorIds = new bytes32[](2);
        evaluatorIds[0] = EVALUATOR_ID;
        evaluatorIds[1] = keccak256("evaluator-2");

        bytes32[] memory entityIds = new bytes32[](1);
        entityIds[0] = ENTITY_ID;

        bool[] memory decisions = new bool[](2);
        decisions[0] = false;
        decisions[1] = true;

        vm.expectRevert(TrustGraph.LengthMismatch.selector);
        vm.prank(AUTHORIZED_EVALUATOR);
        trustGraph.batchSetTrustDecisions(evaluatorIds, entityIds, decisions);

        bool storedDecision = trustGraph.getTrustDecision(EVALUATOR_ID, ENTITY_ID);
        assertTrue(storedDecision, "reverted batch must not overwrite prior state");
    }
}
