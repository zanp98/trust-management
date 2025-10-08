// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TrustGraph {
    event TrustResultRecorded(bytes32 indexed evaluator, bytes32 indexed entity, bool decision);

    mapping(bytes32 => bool) private trustDecisions;

    function _key(bytes32 evaluator, bytes32 entity) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(evaluator, entity));
    }

    function setTrustDecision(bytes32 evaluator, bytes32 entity, bool trusted) external {
        bytes32 key = _key(evaluator, entity);
        trustDecisions[key] = trusted;
        emit TrustResultRecorded(evaluator, entity, trusted);
    }

    function batchSetTrustDecisions(
        bytes32[] calldata evaluators,
        bytes32[] calldata entities,
        bool[] calldata decisions
    ) external {
        require(
            evaluators.length == entities.length &&
                entities.length == decisions.length,
            "Length mismatch"
        );
        for (uint256 i = 0; i < evaluators.length; i++) {
            bytes32 key = _key(evaluators[i], entities[i]);
            trustDecisions[key] = decisions[i];
            emit TrustResultRecorded(evaluators[i], entities[i], decisions[i]);
        }
    }

    function getTrustDecision(bytes32 evaluator, bytes32 entity) external view returns (bool) {
        return trustDecisions[_key(evaluator, entity)];
    }
}
