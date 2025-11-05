// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TrustGraph {
    error NotEvaluator(address caller);
    error NotAdmin(address caller);
    error ReentrantCall();
    error LengthMismatch();
    error BatchLimitExceeded(uint256 attempted, uint256 allowed);
    error InvalidBatchLimit();
    error AggregatorNotAuthorized(address caller);
    error RequestNotFound(bytes32 requestId);
    error RequestExpired(bytes32 requestId, uint64 deadline, uint64 currentTime);
    error InvalidSubject();

    event TrustResultRecorded(
        bytes32 indexed evaluator,
        bytes32 indexed entity,
        bool decision,
        bytes32 credentialHash,
        address indexed publisher
    );
    event EvaluatorUpdated(address indexed evaluator, bool allowed);
    event BatchLimitUpdated(uint256 limit);
    event AggregatorUpdated(address indexed aggregator);
    event TrustOracleRequested(bytes32 indexed requestId, bytes32 indexed subject, address requester, uint64 deadline);
    event TrustOracleFulfilled(
        bytes32 indexed requestId,
        bytes32 indexed subject,
        bool decision,
        uint256 score,
        uint256 flags,
        uint64 asOf,
        bytes32 policyHash,
        address indexed submitter
    );

    address private immutable admin;
    mapping(address => bool) private evaluators;
    address private aggregator;

    mapping(bytes32 => bool) private trustDecisions;
    mapping(bytes32 => bytes32) private credentialReferences;

    struct TrustMetrics {
        bool decision;
        uint256 score;
        uint256 flags;
        uint64 asOf;
        bytes32 policyHash;
    }

    struct PendingRequest {
        bytes32 subject;
        uint64 deadline;
        bool exists;
    }

    struct OracleReport {
        bytes32 subject;
        bool decision;
        uint256 score;
        uint256 flags;
        uint64 asOf;
        bytes32 policyHash;
    }

    mapping(bytes32 => TrustMetrics) private subjectMetrics;
    mapping(bytes32 => PendingRequest) private pendingRequests;
    uint256 private requestNonce;

    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;
    uint256 private maxBatchSize;
    bytes32 private constant DON_EVALUATOR = keccak256("MINI_DON_EVALUATOR");

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

    function getTrustMetrics(bytes32 subject) external view returns (TrustMetrics memory) {
        return subjectMetrics[subject];
    }

    function updateEvaluator(address evaluator, bool allowed) external onlyAdmin nonReentrant {
        evaluators[evaluator] = allowed;
        emit EvaluatorUpdated(evaluator, allowed);
    }

    function setAggregator(address newAggregator) external onlyAdmin nonReentrant {
        aggregator = newAggregator;
        emit AggregatorUpdated(newAggregator);
    }

    function getAggregator() external view returns (address) {
        return aggregator;
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

    function requestTrustReport(bytes32 subject, uint64 ttlSeconds) external onlyAdmin nonReentrant returns (bytes32) {
        if (subject == bytes32(0)) {
            revert InvalidSubject();
        }
        uint64 ttl = ttlSeconds > 0 ? ttlSeconds : uint64(1 hours);
        uint64 deadline = uint64(block.timestamp + ttl);
        bytes32 requestId = keccak256(abi.encodePacked(subject, block.timestamp, msg.sender, requestNonce));
        requestNonce += 1;
        pendingRequests[requestId] = PendingRequest({subject: subject, deadline: deadline, exists: true});
        emit TrustOracleRequested(requestId, subject, msg.sender, deadline);
        return requestId;
    }

    function fulfillTrustReport(bytes32 requestId, OracleReport calldata report) external nonReentrant {
        if (msg.sender != aggregator || aggregator == address(0)) {
            revert AggregatorNotAuthorized(msg.sender);
        }
        PendingRequest memory request = pendingRequests[requestId];
        if (!request.exists) {
            revert RequestNotFound(requestId);
        }
        if (report.subject != request.subject || report.subject == bytes32(0)) {
            revert InvalidSubject();
        }
        if (block.timestamp > request.deadline) {
            revert RequestExpired(requestId, request.deadline, uint64(block.timestamp));
        }
        delete pendingRequests[requestId];

        subjectMetrics[report.subject] = TrustMetrics({
            decision: report.decision,
            score: report.score,
            flags: report.flags,
            asOf: report.asOf,
            policyHash: report.policyHash
        });

        _recordDecision(DON_EVALUATOR, report.subject, report.decision, bytes32(0));

        emit TrustOracleFulfilled(
            requestId,
            report.subject,
            report.decision,
            report.score,
            report.flags,
            report.asOf,
            report.policyHash,
            msg.sender
        );
    }
}
