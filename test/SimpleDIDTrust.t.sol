// test/SimpleDIDTrust.t.sol
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "../src/contracts/SimpleDIDTrust.sol";

contract SimpleDIDTrustTest is Test {
    SimpleDIDTrust sdt;

    function setUp() public {
        // Deploy a new instance of your contract
        sdt = new SimpleDIDTrust();
    }

    function testRegisterDID() public {
        // Because onlyOwner can call registerDID, so let's do it as the 'owner' (msg.sender in setUp).
        // In Foundry’s default test environment, 'address(this)' is effectively the deployer.

        sdt.registerDID("did:example:123", 1);
        assertEq(sdt.checkTrust("did:example:123"), 1, "Should be trusted");
    }
}
