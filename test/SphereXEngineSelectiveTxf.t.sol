// SPDX-License-Identifier: UNLICENSED
// (c) SphereX 2023 Terms&Conditions

pragma solidity >=0.6.2;

import "forge-std/Test.sol";
import "./Utils/CFUtils.sol";
import "../src/SphereXEngine.sol";

contract SphereXEngineSelectiveTxfTest is Test, CFUtils {
    address random_address = 0x6A08098568eE90b71dD757F070D79364197f944B;
    uint256[] enforcedFunctions;

    function setUp() public {
        spherex_engine = new SphereXEngine();
        allowed_senders.push(address(this));
        spherex_engine.addAllowedSender(allowed_senders);
        spherex_engine.configureRules(bytes8(SELECTIVE_TXF));
    }

    //  ============ Test for the management functions  ============

    function test_SelectiveTxf_not_included_function() public {
        allowed_cf_storage = [int256(1), -1];

        // nothing should happen since we didnt set the function for enforcment
        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendExternalNumberToEngine(allowed_cf_storage[i]);
        }
    }

    function test_SelectiveTxf_included_function() public {
        allowed_cf_storage = [int256(1), -1];
        enforcedFunctions = [uint256(1)];
        spherex_engine.includeEnforcedFunctions(enforcedFunctions);

        // expect revert when exitins the flow since we didnt approved it
        sendExternalNumberToEngine(allowed_cf_storage[0]);
        vm.expectRevert("SphereX error: disallowed tx pattern");
        sendExternalNumberToEngine(allowed_cf_storage[1]);
    }

    function test_SelectiveTxf_included_function_allowed_pattern() public {
        allowed_cf_storage = [int256(1), -1];
        addAllowedPattern();
        enforcedFunctions = [uint256(1)];
        spherex_engine.includeEnforcedFunctions(enforcedFunctions);

        sendExternalNumberToEngine(allowed_cf_storage[0]);
        sendExternalNumberToEngine(allowed_cf_storage[1]);
    }

    function test_SelectiveTxf_one_included_one_not() public {
        // unlike txf, because we only include function 2 for enforcment then the
        // flow 1,-1 will not be checked, only the complete flow, since we will strt enforcment
        // after 2 will be sent to the engine.
        allowed_cf_storage = [int256(1), -1, 2, -2];
        addAllowedPattern();

        enforcedFunctions = [uint256(2)];
        spherex_engine.includeEnforcedFunctions(enforcedFunctions);

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendExternalNumberToEngine(allowed_cf_storage[i]);
        }
    }

    function test_SelectiveTxf_one_included_one_not__pattern_not_approved() public {
        // this test is to make sure the previous was working correctly
        allowed_cf_storage = [int256(1), -1, 2, -2];

        enforcedFunctions = [uint256(2)];
        spherex_engine.includeEnforcedFunctions(enforcedFunctions);

        sendExternalNumberToEngine(allowed_cf_storage[0]);
        sendExternalNumberToEngine(allowed_cf_storage[1]);
        sendExternalNumberToEngine(allowed_cf_storage[2]);
        vm.expectRevert("SphereX error: disallowed tx pattern");
        sendExternalNumberToEngine(allowed_cf_storage[3]);
    }

    function test_SelectiveTxf_check_we_stop_enforce_in_next_tx() public {
        // this test is to make sure the previous was working correctly
        allowed_cf_storage = [int256(1), -1, 2, -2];
        addAllowedPattern();

        enforcedFunctions = [uint256(2)];
        spherex_engine.includeEnforcedFunctions(enforcedFunctions);

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendExternalNumberToEngine(allowed_cf_storage[i]);
        }

        vm.roll(3);

        allowed_cf_storage = [int256(1), -1, 3, -3, 1, 5, -5, -1];
        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendExternalNumberToEngine(allowed_cf_storage[i]);
        }
    }

    function test_SelectiveTxf_check_we_keep_enforce_in_current_tx() public {
        // this test is to make sure the previous was working correctly
        allowed_cf_storage = [int256(1), -1, 2, -2];
        addAllowedPattern();

        enforcedFunctions = [uint256(2)];
        spherex_engine.includeEnforcedFunctions(enforcedFunctions);

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendExternalNumberToEngine(allowed_cf_storage[i]);
        }

        sendExternalNumberToEngine(3);
        vm.expectRevert("SphereX error: disallowed tx pattern");
        sendExternalNumberToEngine(-3);
    }
}
