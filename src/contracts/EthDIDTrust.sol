// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "lib/ethr-did-registry/contracts/EthereumDIDRegistry.sol";

contract EthDIDTrust {
    EthereumDIDRegistry public didRegistry;

    // Mapping: DID address → trust level (1 = trusted, 0 = untrusted)
    mapping(address => uint8) public trustLevels;

    // Mapping: DID address → owner
    mapping(address => address) public didOwner;

    // Track number of DIDs issued
    uint256 private didCounter;

    // Contract owner (deployer)
    address public owner;

    // Events for logging DID creation, trust updates, and revocation
    event DIDRegistered(address indexed did, uint8 trustLevel);
    event DIDCreated(address indexed did, address indexed owner);
    event DIDRevoked(address indexed did);
    event DIDOwnershipTransferred(address indexed did, address indexed newOwner);

    constructor(address registryAddr) {
        owner = msg.sender;
        didRegistry = EthereumDIDRegistry(registryAddr);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier onlyDIDOwner(address did) {
        require(didOwner[did] == msg.sender, "Caller is not the DID owner");
        _;
    }

    /**
     * @dev Register a new DID with an initial trust value (1 or 0).
     */
    function registerDID(address identity, address delegate, uint8 initialTrust) external onlyOwner {
        require(initialTrust == 0 || initialTrust == 1, "Trust must be 0 or 1");
        require(trustLevels[identity] == 0, "DID already registered"); // Prevent double registration

        // Add delegate in `EthereumDIDRegistry`
        didRegistry.addDelegate(identity, keccak256("veriKey"), delegate, block.timestamp + 365 days);

        // Assign trust level
        trustLevels[identity] = initialTrust;
        didOwner[identity] = msg.sender;

        emit DIDRegistered(identity, initialTrust);
        emit DIDCreated(identity, msg.sender);
    }

    /**
     * @dev Update the trust value for an existing DID (1 or 0).
     */
    function setTrustValue(address did, uint8 newTrust) external onlyOwner {
        require(trustLevels[did] != 0, "DID not registered");
        require(newTrust == 0 || newTrust == 1, "Trust must be 0 or 1");

        trustLevels[did] = newTrust;
        emit DIDRegistered(did, newTrust);
    }

    /**
     * @dev Check the trust status of a DID. Returns 1 if trusted, else 0.
     */
    function checkTrust(address did) external view returns (uint8) {
        return trustLevels[did];
    }

    /**
     * @dev Get the owner of a DID.
     */
    function getDIDOwner(address did) external view returns (address) {
        return didOwner[did];
    }

    /**
     * @dev Revoke a DID (remove all trust and delete all delegates).
     */
    function revokeDID(address did) external onlyDIDOwner(did) {
        require(trustLevels[did] != 0, "DID not registered");

        // Remove all delegates for this DID
        didRegistry.revokeDelegate(did, keccak256("veriKey"), didOwner[did]);

        // Remove trust and owner reference
        trustLevels[did] = 0;
        didOwner[did] = address(0);

        emit DIDRevoked(did);
    }

    /**
     * @dev Transfer ownership of a DID to a new address.
     */
    function transferDIDOwnership(address did, address newOwner) external onlyDIDOwner(did) {
        require(newOwner != address(0), "New owner cannot be zero address");

        didOwner[did] = newOwner;
        emit DIDOwnershipTransferred(did, newOwner);
    }
}
