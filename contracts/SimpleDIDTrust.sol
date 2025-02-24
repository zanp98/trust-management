// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract SimpleDIDTrust {

    // A struct to hold info about the DID
    struct DIDInfo {
        bool registered;   // indicates if this DID is known
        uint8 trustLevel;  // 1 means "trusted", 0 means "untrusted"
    }

    // Mapping from a DID string to its info
    mapping(string => DIDInfo) private didRegistry;

    // Contract owner (the account that deployed the contract)
    address public owner;

    // Event for logging new registrations or updates
    event DIDRegistered(string indexed did, uint8 trustLevel);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    /**
     * @dev Register a new DID with an initial trust (1 or 0).
     */
    function registerDID(string memory did, uint8 initialTrust) external onlyOwner {
        require(initialTrust == 0 || initialTrust == 1, "Trust must be 0 or 1");
        require(!didRegistry[did].registered, "DID already registered");

        didRegistry[did] = DIDInfo({
            registered: true,
            trustLevel: initialTrust
        });

        emit DIDRegistered(did, initialTrust);
    }

    /**
     * @dev Update the trust value for an existing DID (1 or 0).
     */
    function setTrustValue(string memory did, uint8 newTrust) external onlyOwner {
        require(didRegistry[did].registered, "DID not registered yet");
        require(newTrust == 0 || newTrust == 1, "Trust must be 0 or 1");

        didRegistry[did].trustLevel = newTrust;
        emit DIDRegistered(did, newTrust);
    }

    /**
     * @dev Check the trust status of a DID. Returns 1 if trusted, else 0.
     */
    function checkTrust(string memory did) external view returns (uint8) {
        if (!didRegistry[did].registered) {
            return 0; // not registered => untrusted
        }
        return didRegistry[did].trustLevel;
    }
}
