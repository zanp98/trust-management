// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "../src/contracts/EthDIDTrust.sol";

contract EthDIDTrustTest is Test {
    EthDIDTrust trustContract;
    EthereumDIDRegistry registry;
    
    // Test addresses
    address owner = address(this); // Owner of the EthDIDTrust contract (deployer)
    address user1 = address(0x1234); // The DID owner
    address user2 = address(0x5678); // Delegate
    address user3 = address(0x9ABC); // New DID owner

    function setUp() public {
        registry = new EthereumDIDRegistry();
        trustContract = new EthDIDTrust(address(registry));

        // Step 1: Register user1 as a valid identity
        vm.prank(user1);
        registry.setAttribute(user1, keccak256("didOwner"), abi.encodePacked(user1), block.timestamp + 365 days);

        // Step 2: Allow EthDIDTrust contract to act on behalf of user1
        vm.prank(user1);
        registry.addDelegate(user1, keccak256("veriKey"), address(trustContract), block.timestamp + 365 days);
    }


    function testRegisterDID() public {
        vm.prank(owner); // Simulate the contract owner calling registerDID
        trustContract.registerDID(user1, user2, 1);

        assertEq(trustContract.checkTrust(user1), 1, "DID should be trusted");
        assertEq(trustContract.getDIDOwner(user1), user1, "Owner should be user1");
    }

    function testTransferDIDOwnership() public {
        vm.prank(owner);
        trustContract.registerDID(user1, user2, 1);

        vm.prank(user1); // Simulate the DID owner calling transfer
        trustContract.transferDIDOwnership(user1, user3);

        assertEq(trustContract.getDIDOwner(user1), user3, "DID ownership should be transferred to user3");
    }

    function testRevokeDID() public {
        vm.prank(owner);
        trustContract.registerDID(user1, user2, 1);

        vm.prank(user1); // Simulate the DID owner calling revoke
        trustContract.revokeDID(user1);

        assertEq(trustContract.checkTrust(user1), 0, "DID should be revoked");
        assertEq(trustContract.getDIDOwner(user1), address(0), "DID owner should be reset");
    }
}
