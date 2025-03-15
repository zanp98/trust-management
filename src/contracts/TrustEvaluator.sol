// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract TrustEvaluator {
    mapping(address => bool) public trustedEntities;

    event TrustUpdated(address indexed entity, bool isTrusted);

    // Set trust status (Normally this would come from a reasoner)
    function setTrustStatus(address entity, bool isTrusted) public {
        trustedEntities[entity] = isTrusted;
        emit TrustUpdated(entity, isTrusted);
    }

    // Check if an entity is trusted
    function isTrusted(address entity) public view returns (bool) {
        return trustedEntities[entity];
    }
}
