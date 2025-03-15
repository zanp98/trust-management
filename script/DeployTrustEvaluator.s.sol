// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "../src/contracts/TrustEvaluator.sol";

contract DeployTrustEvaluator is Script {
    function run() external {
        vm.startBroadcast();
        TrustEvaluator trustEvaluator = new TrustEvaluator();
        console.log("TrustEvaluator deployed at:", address(trustEvaluator));
        vm.stopBroadcast();
    }
}
