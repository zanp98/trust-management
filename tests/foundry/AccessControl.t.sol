// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../chain/contracts/TrustGraph.sol";

contract AccessControlTest is Test {
    TrustGraph private trustGraph;

    address private constant ADMIN = address(0xA11CE);
    address private constant AUTHORIZED_EVALUATOR = address(0xE1);
    address private constant SECOND_EVALUATOR = address(0xE2);
    address private constant INTRUDER = address(0xBEEF);

    bytes32 private constant EVALUATOR_ID = keccak256("evaluator-1");
    bytes32 private constant ENTITY_ID = keccak256("entity-1");
    bytes32 private constant SECOND_ENTITY_ID = keccak256("entity-2");

    function setUp() public {
        vm.prank(ADMIN);
        trustGraph = new TrustGraph();

        vm.prank(ADMIN);
        trustGraph.updateEvaluator(AUTHORIZED_EVALUATOR, true);
    }

    function testAuthorizedEvaluatorCanPublishDecision() public {
        vm.prank(AUTHORIZED_EVALUATOR);
        trustGraph.setTrustDecision(EVALUATOR_ID, ENTITY_ID, true);

        bool storedDecision = trustGraph.getTrustDecision(EVALUATOR_ID, ENTITY_ID);
        assertTrue(storedDecision, "authorized evaluator should persist trust decision");
    }

    function testUnauthorizedCallerIsRejected() public {
        vm.expectRevert(abi.encodeWithSelector(TrustGraph.NotEvaluator.selector, INTRUDER));

        vm.prank(INTRUDER);
        trustGraph.setTrustDecision(EVALUATOR_ID, ENTITY_ID, true);
    }

    function testAdminCanGrantAndRevokeEvaluatorRole() public {
        vm.expectEmit(false, false, false, true);
        emit TrustGraph.EvaluatorUpdated(SECOND_EVALUATOR, true);
        vm.prank(ADMIN);
        trustGraph.updateEvaluator(SECOND_EVALUATOR, true);

        assertTrue(trustGraph.isEvaluator(SECOND_EVALUATOR), "new evaluator must be registered");

        vm.prank(SECOND_EVALUATOR);
        trustGraph.setTrustDecision(EVALUATOR_ID, SECOND_ENTITY_ID, false);
        assertFalse(
            trustGraph.getTrustDecision(EVALUATOR_ID, SECOND_ENTITY_ID),
            "new evaluator should write decisions before revocation"
        );

        vm.expectEmit(false, false, false, true);
        emit TrustGraph.EvaluatorUpdated(SECOND_EVALUATOR, false);
        vm.prank(ADMIN);
        trustGraph.updateEvaluator(SECOND_EVALUATOR, false);

        assertFalse(trustGraph.isEvaluator(SECOND_EVALUATOR), "revoked evaluator must be removed");

        vm.expectRevert(abi.encodeWithSelector(TrustGraph.NotEvaluator.selector, SECOND_EVALUATOR));
        vm.prank(SECOND_EVALUATOR);
        trustGraph.setTrustDecision(EVALUATOR_ID, SECOND_ENTITY_ID, true);
    }

    function testNonAdminCannotUpdateEvaluator() public {
        vm.expectRevert(abi.encodeWithSelector(TrustGraph.NotAdmin.selector, AUTHORIZED_EVALUATOR));
        vm.prank(AUTHORIZED_EVALUATOR);
        trustGraph.updateEvaluator(SECOND_EVALUATOR, true);
    }
}
