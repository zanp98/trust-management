// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../chain/contracts/TrustGraph.sol";

contract PublishWithCredentialTest is Test {
    event TrustResultRecorded(
        bytes32 indexed evaluator,
        bytes32 indexed entity,
        bool decision,
        bytes32 credentialHash,
        address indexed publisher
    );

    TrustGraph private trustGraph;

    address private constant ADMIN = address(0xA11CE);
    address private constant AUTHORIZED_EVALUATOR = address(0xE1);

    bytes32 private constant EVALUATOR_ID = keccak256("evaluator-1");
    bytes32 private constant ENTITY_ID = keccak256("entity-1");
    bytes32 private constant CREDENTIAL_HASH = keccak256("vc-hash-1");

    function setUp() public {
        vm.prank(ADMIN);
        trustGraph = new TrustGraph();

        vm.prank(ADMIN);
        trustGraph.updateEvaluator(AUTHORIZED_EVALUATOR, true);
    }

    function testPublishesDecisionWithCredentialLink() public {
        vm.expectEmit(true, true, true, true);
        emit TrustResultRecorded(EVALUATOR_ID, ENTITY_ID, true, CREDENTIAL_HASH, AUTHORIZED_EVALUATOR);

        vm.prank(AUTHORIZED_EVALUATOR);
        trustGraph.setTrustDecisionWithCredential(EVALUATOR_ID, ENTITY_ID, true, CREDENTIAL_HASH);

        bool storedDecision = trustGraph.getTrustDecision(EVALUATOR_ID, ENTITY_ID);
        bytes32 storedCredential = trustGraph.getCredentialHash(EVALUATOR_ID, ENTITY_ID);

        assertTrue(storedDecision, "decision must be stored");
        assertEq(storedCredential, CREDENTIAL_HASH, "stored credential hash must match");
    }
}
