// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../chain/contracts/TrustGraph.sol";

contract OracleWorkflowTest is Test {
    TrustGraph private trustGraph;

    address private constant ADMIN = address(0xA11CE);
    address private constant AGGREGATOR = address(0xB0B);
    bytes32 private constant SUBJECT = keccak256("entity-1");
    bytes32 private constant POLICY_HASH = keccak256("policy-v1");
    bytes32 private constant DON_EVALUATOR_ID = keccak256("MINI_DON_EVALUATOR");

    function setUp() public {
        vm.prank(ADMIN);
        trustGraph = new TrustGraph();

        vm.prank(ADMIN);
        trustGraph.setAggregator(AGGREGATOR);
    }

    function testRequestTrustReportEmitsEvent() public {
        uint64 ttl = 3600;
        bytes32 expectedId = keccak256(abi.encodePacked(SUBJECT, block.timestamp, ADMIN, uint256(0)));
        uint64 expectedDeadline = uint64(block.timestamp + ttl);
        vm.expectEmit(true, true, true, true);
        emit TrustGraph.TrustOracleRequested(expectedId, SUBJECT, ADMIN, expectedDeadline);

        vm.prank(ADMIN);
        trustGraph.requestTrustReport(SUBJECT, ttl);
    }

    function testOnlyAggregatorCanFulfill() public {
        vm.prank(ADMIN);
        bytes32 requestId = trustGraph.requestTrustReport(SUBJECT, 3600);

        TrustGraph.OracleReport memory report = TrustGraph.OracleReport({
            subject: SUBJECT,
            decision: true,
            score: 9000,
            flags: 1,
            asOf: uint64(block.timestamp),
            policyHash: POLICY_HASH
        });

        vm.expectRevert(abi.encodeWithSelector(TrustGraph.AggregatorNotAuthorized.selector, address(this)));
        trustGraph.fulfillTrustReport(requestId, report);
    }

    function testFulfillUpdatesMetricsAndDecision() public {
        vm.prank(ADMIN);
        bytes32 requestId = trustGraph.requestTrustReport(SUBJECT, 3600);

        TrustGraph.OracleReport memory report = TrustGraph.OracleReport({
            subject: SUBJECT,
            decision: true,
            score: 8750,
            flags: 3,
            asOf: uint64(block.timestamp),
            policyHash: POLICY_HASH
        });

        vm.expectEmit(true, true, true, true);
        emit TrustGraph.TrustOracleFulfilled(
            requestId,
            SUBJECT,
            true,
            8750,
            3,
            report.asOf,
            POLICY_HASH,
            AGGREGATOR
        );

        vm.prank(AGGREGATOR);
        trustGraph.fulfillTrustReport(requestId, report);

        TrustGraph.TrustMetrics memory metrics = trustGraph.getTrustMetrics(SUBJECT);
        assertEq(metrics.decision, true, "decision mismatch");
        assertEq(metrics.score, 8750, "score mismatch");
        assertEq(metrics.flags, 3, "flags mismatch");
        assertEq(metrics.policyHash, POLICY_HASH, "policy hash mismatch");

        bool storedDecision = trustGraph.getTrustDecision(DON_EVALUATOR_ID, SUBJECT);
        assertTrue(storedDecision, "aggregated decision not stored");
    }

    function testFulfillAfterDeadlineReverts() public {
        uint64 ttl = 10;
        vm.warp(1_000);

        vm.prank(ADMIN);
        bytes32 requestId = trustGraph.requestTrustReport(SUBJECT, ttl);
        uint64 deadline = uint64(block.timestamp + ttl);

        vm.warp(block.timestamp + ttl + 1);

        TrustGraph.OracleReport memory report = TrustGraph.OracleReport({
            subject: SUBJECT,
            decision: false,
            score: 1000,
            flags: 0,
            asOf: uint64(block.timestamp),
            policyHash: POLICY_HASH
        });

        vm.expectRevert(
            abi.encodeWithSelector(
                TrustGraph.RequestExpired.selector,
                requestId,
                deadline,
                uint64(block.timestamp)
            )
        );
        vm.prank(AGGREGATOR);
        trustGraph.fulfillTrustReport(requestId, report);
    }
}
