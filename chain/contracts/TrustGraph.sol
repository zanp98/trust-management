// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TrustGraph {
    error NotEvaluator(address caller);
    error NotAdmin(address caller);
    error ReentrantCall();
    error LengthMismatch();
    error BatchLimitExceeded(uint256 attempted, uint256 allowed);
    error InvalidBatchLimit();

    event TrustResultRecorded(
        bytes32 indexed evaluator,
        bytes32 indexed entity,
        bool decision,
        bytes32 credentialHash,
        address indexed publisher
    );
    event EvaluatorUpdated(address indexed evaluator, bool allowed);
    event BatchLimitUpdated(uint256 limit);

    address private immutable admin;
    mapping(address => bool) private evaluators;

    mapping(bytes32 => bool) private trustDecisions;
    mapping(bytes32 => bytes32) private credentialReferences;

    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;
    uint256 private maxBatchSize;

    modifier onlyAdmin() {
        if (msg.sender != admin) {
            revert NotAdmin(msg.sender);
        }
        _;
    }

    modifier onlyEvaluator() {
        if (!evaluators[msg.sender]) {
            revert NotEvaluator(msg.sender);
        }
        _;
    }

    modifier nonReentrant() {
        if (_status == _ENTERED) {
            revert ReentrantCall();
        }
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    constructor() {
        admin = msg.sender;
        evaluators[msg.sender] = true;
        emit EvaluatorUpdated(msg.sender, true);
        _status = _NOT_ENTERED;
        maxBatchSize = 100;
    }

    function _key(bytes32 evaluator, bytes32 entity) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(evaluator, entity));
    }

    function _recordDecision(bytes32 evaluator, bytes32 entity, bool trusted, bytes32 credentialHash) private {
        bytes32 key = _key(evaluator, entity);
        trustDecisions[key] = trusted;
        credentialReferences[key] = credentialHash;
        emit TrustResultRecorded(evaluator, entity, trusted, credentialHash, msg.sender);
    }

    function _beforeSetTrustDecision(bytes32 evaluator, bytes32 entity, bool trusted) internal virtual {}

    function _enforceBatchLimit(uint256 size) private view {
        if (size > maxBatchSize) {
            revert BatchLimitExceeded(size, maxBatchSize);
        }
    }

    function setTrustDecision(bytes32 evaluator, bytes32 entity, bool trusted)
        external
        onlyEvaluator
        nonReentrant
    {
        _beforeSetTrustDecision(evaluator, entity, trusted);
        _recordDecision(evaluator, entity, trusted, bytes32(0));
    }

    function setTrustDecisionWithCredential(bytes32 evaluator, bytes32 entity, bool trusted, bytes32 credentialHash)
        external
        onlyEvaluator
        nonReentrant
    {
        _beforeSetTrustDecision(evaluator, entity, trusted);
        _recordDecision(evaluator, entity, trusted, credentialHash);
    }

    function batchSetTrustDecisions(
        bytes32[] calldata evaluatorIds,
        bytes32[] calldata entityIds,
        bool[] calldata decisions
    ) external onlyEvaluator nonReentrant {
        uint256 length = evaluatorIds.length;
        if (length != entityIds.length || length != decisions.length) {
            revert LengthMismatch();
        }
        _enforceBatchLimit(length);
        for (uint256 i = 0; i < length; i++) {
            _recordDecision(evaluatorIds[i], entityIds[i], decisions[i], bytes32(0));
        }
    }

    function batchSetTrustDecisionsWithCredentials(
        bytes32[] calldata evaluatorIds,
        bytes32[] calldata entityIds,
        bool[] calldata decisions,
        bytes32[] calldata credentialHashes
    ) external onlyEvaluator nonReentrant {
        uint256 length = evaluatorIds.length;
        if (length != entityIds.length || length != decisions.length || length != credentialHashes.length) {
            revert LengthMismatch();
        }
        _enforceBatchLimit(length);
        for (uint256 i = 0; i < length; i++) {
            _recordDecision(evaluatorIds[i], entityIds[i], decisions[i], credentialHashes[i]);
        }
    }

    function getTrustDecision(bytes32 evaluator, bytes32 entity) external view returns (bool) {
        return trustDecisions[_key(evaluator, entity)];
    }

    function getCredentialHash(bytes32 evaluator, bytes32 entity) external view returns (bytes32) {
        return credentialReferences[_key(evaluator, entity)];
    }

    function updateEvaluator(address evaluator, bool allowed) external onlyAdmin nonReentrant {
        evaluators[evaluator] = allowed;
        emit EvaluatorUpdated(evaluator, allowed);
    }

    function setBatchLimit(uint256 newLimit) external onlyAdmin nonReentrant {
        if (newLimit == 0) {
            revert InvalidBatchLimit();
        }
        maxBatchSize = newLimit;
        emit BatchLimitUpdated(newLimit);
    }

    function getBatchLimit() external view returns (uint256) {
        return maxBatchSize;
    }

    function isEvaluator(address account) external view returns (bool) {
        return evaluators[account];
    }
}
