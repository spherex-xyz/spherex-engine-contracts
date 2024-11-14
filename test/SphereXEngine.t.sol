// SPDX-License-Identifier: UNLICENSED
// (c) SphereX 2023 Terms&Conditions

pragma solidity >=0.6.2;

import "forge-std/Test.sol";
import "./Utils/CFUtils.sol";
import "../src/SphereXEngine.sol";

contract SphereXEngineTest is Test, CFUtils {
    address random_address = 0x6A08098568eE90b71dD757F070D79364197f944B;

    modifier activateRule(bytes8 rule) {
        // This will make forge call the function with 1 and 2 as inputs!
        uint16 assumeVariable = uint8(uint16(uint64(rule)));
        vm.assume(assumeVariable > 0 && assumeVariable < 3);
        spherex_engine.configureRules(bytes8(uint64(assumeVariable)));

        _;
    }

    function setUp() public {
        spherex_engine = new SphereXEngine();
        allowed_senders.push(address(this));
        spherex_engine.addAllowedSender(allowed_senders);
    }

    //  ============ Test for the management functions  ============

    function test_passOwnership() public {
        spherex_engine.beginDefaultAdminTransfer(random_address);
        vm.warp(block.timestamp + 2 days);
        vm.prank(random_address);
        spherex_engine.acceptDefaultAdminTransfer();
    }

    function test_onlyAdminCanGrantOperatorRoles() public {
        bytes32 OPERATOR_ROLE = spherex_engine.OPERATOR_ROLE();

        vm.prank(random_address);
        vm.expectRevert();
        spherex_engine.grantRole(OPERATOR_ROLE, random_address);

        spherex_engine.grantRole(OPERATOR_ROLE, random_address);
    }

    function test_addAndRemoveOperator() public {
        vm.prank(random_address);
        vm.expectRevert("SphereX error: operator required");
        spherex_engine.addAllowedSender(allowed_senders);

        spherex_engine.grantRole(spherex_engine.OPERATOR_ROLE(), random_address);
        vm.prank(random_address);
        allowed_senders = [address(this)];
        spherex_engine.removeAllowedSender(allowed_senders);

        spherex_engine.revokeRole(spherex_engine.OPERATOR_ROLE(), random_address);
        vm.prank(random_address);
        vm.expectRevert("SphereX error: operator required");
        spherex_engine.addAllowedSender(allowed_senders);
    }

    function test_addAllowedSender() public activateRule(CF) {
        allowed_senders = [random_address];
        spherex_engine.addAllowedSender(allowed_senders);
        vm.prank(random_address);
        sendInternalNumberToEngine(1);
    }

    function test_removeAllowedSender(bytes8 rule) public activateRule(rule) {
        allowed_senders = [address(this)];
        spherex_engine.removeAllowedSender(allowed_senders);

        vm.expectRevert("SphereX error: disallowed sender");
        sendInternalNumberToEngine(1);

        assertFlowStorageSlotsInInitialState();
    }

    function test_addAllowedPatterns_two_patterns() public activateRule(CF) {
        int256[2] memory allowed_cf = [int256(1), -1];
        uint216 allowed_cf_hash = 1;
        for (uint256 i = 0; i < allowed_cf.length; i++) {
            allowed_cf_hash = uint216(bytes27(keccak256(abi.encode(int256(allowed_cf[i]), allowed_cf_hash))));
        }

        int256[2] memory allowed_cf_2 = [int256(2), -2];
        uint216 allowed_cf_hash_2 = 1;
        for (uint256 i = 0; i < allowed_cf_2.length; i++) {
            allowed_cf_hash_2 = uint216(bytes27(keccak256(abi.encode(int256(allowed_cf_2[i]), allowed_cf_hash_2))));
        }

        allowed_patterns = [allowed_cf_hash, allowed_cf_hash_2];
        spherex_engine.addAllowedPatterns(allowed_patterns);

        for (uint256 i = 0; i < allowed_cf.length; i++) {
            sendInternalNumberToEngine(allowed_cf[i]);
        }

        assertFlowStorageSlotsInInitialState();

        for (uint256 i = 0; i < allowed_cf_2.length; i++) {
            sendInternalNumberToEngine(allowed_cf_2[i]);
        }

        assertFlowStorageSlotsInInitialState();
    }

    function test_removeAllowedPatterns(bytes8 rule) public activateRule(rule) {
        allowed_cf_storage = [int256(1), -1];
        uint216 allowed_cf_hash = addAllowedPattern();

        allowed_patterns = [allowed_cf_hash];
        spherex_engine.removeAllowedPatterns(allowed_patterns);

        sendInternalNumberToEngine(1);
        vm.expectRevert("SphereX error: disallowed tx pattern");
        sendInternalNumberToEngine(-1);
    }

    // remove two cf and check that the first one was removed
    function test_removeAllowedPatterns_check_first_pattern_removed() public activateRule(CF) {
        allowed_cf_storage = [int256(1), -1];
        uint216 allowed_cf_hash = addAllowedPattern();
        allowed_cf_storage = [int256(2), -2];
        addAllowedPattern();
        allowed_cf_storage = [int256(3), -3];
        uint216 allowed_cf_hash_3 = addAllowedPattern();

        allowed_patterns = [allowed_cf_hash, allowed_cf_hash_3];
        spherex_engine.removeAllowedPatterns(allowed_patterns);

        sendInternalNumberToEngine(2);
        sendInternalNumberToEngine(-2);

        sendInternalNumberToEngine(1);
        vm.expectRevert("SphereX error: disallowed tx pattern");
        sendInternalNumberToEngine(-1);
    }

    // remove two cf and check that the second one was removed
    function test_removeAllowedPatterns_check_second_pattern_removed() public activateRule(CF) {
        allowed_cf_storage = [int256(1), -1];
        uint216 allowed_cf_hash = addAllowedPattern();
        allowed_cf_storage = [int256(2), -2];
        addAllowedPattern();
        allowed_cf_storage = [int256(3), -3];
        uint216 allowed_cf_hash_3 = addAllowedPattern();

        allowed_patterns = [allowed_cf_hash, allowed_cf_hash_3];
        spherex_engine.removeAllowedPatterns(allowed_patterns);

        sendInternalNumberToEngine(2);
        sendInternalNumberToEngine(-2);

        sendInternalNumberToEngine(3);
        vm.expectRevert("SphereX error: disallowed tx pattern");
        sendInternalNumberToEngine(-3);
    }

    function test_badRulesConfig() public {
        vm.expectRevert("SphereX error: illegal rules combination");
        spherex_engine.configureRules(bytes8(uint64(3)));
        vm.expectRevert("SphereX error: illegal rules combination");
        spherex_engine.configureRules(bytes8(uint64(5)));
        vm.expectRevert("SphereX error: illegal rules combination");
        spherex_engine.configureRules(bytes8(uint64(6)));
        spherex_engine.configureRules(bytes8(uint64(1)));
        spherex_engine.configureRules(bytes8(uint64(2)));
        spherex_engine.configureRules(bytes8(uint64(4)));
    }

    // ============ Modifiers  ============

    function test_onlyOwner() public {
        vm.expectRevert("SphereX error: operator required");
        // change caller to random address
        vm.prank(random_address);
        allowed_senders = [address(this)];
        spherex_engine.removeAllowedSender(allowed_senders);
    }

    function test_onlyApprovedSenders_sphereXValidateInternalPre() public {
        spherex_engine.configureRules(CF);
        vm.expectRevert("SphereX error: disallowed sender");
        vm.prank(random_address);
        sendInternalNumberToEngine(1);
    }

    function test_onlyApprovedSenders_sphereXValidatePre() public {
        spherex_engine.configureRules(CF);
        vm.expectRevert("SphereX error: disallowed sender");
        vm.prank(random_address);
        spherex_engine.sphereXValidatePre(1, address(this), msg.data);
    }

    function test_onlyApprovedSenders_sphereXValidatePost() public {
        spherex_engine.configureRules(CF);
        vm.expectRevert("SphereX error: disallowed sender");
        vm.prank(random_address);
        bytes32[] memory emptyArray = new bytes32[](0);
        spherex_engine.sphereXValidatePost(1, 0, emptyArray, emptyArray);
    }

    function test_returnsIfNotActivated_sphereXValidateInternalPre() public {
        spherex_engine.deactivateAllRules();
        sendInternalNumberToEngine(1);
        sendInternalNumberToEngine(-1);

        assertFlowStorageSlotsInInitialState();
    }

    function test_returnsIfNotActivated_sphereXValidatePrePost() public {
        spherex_engine.deactivateAllRules();
        spherex_engine.sphereXValidatePre(1, address(this), msg.data);
        bytes32[] memory emptyArray = new bytes32[](0);
        spherex_engine.sphereXValidatePost(-1, 0, emptyArray, emptyArray);

        assertFlowStorageSlotsInInitialState();
    }

    function test_activateRule1_not_owner() public {
        spherex_engine.configureRules(CF);

        vm.expectRevert("SphereX error: operator required");
        vm.prank(random_address);
        spherex_engine.configureRules(CF);

        assertFlowStorageSlotsInInitialState();
    }

    function test_activateRule2_not_owner() public {
        spherex_engine.configureRules(CF);

        vm.expectRevert("SphereX error: operator required");
        vm.prank(random_address);
        spherex_engine.configureRules(PREFIX_TX_FLOW);

        assertFlowStorageSlotsInInitialState();
    }

    function test_deactivateAllRules_not_owner() public {
        spherex_engine.deactivateAllRules();

        vm.expectRevert("SphereX error: operator required");
        vm.prank(random_address);
        spherex_engine.deactivateAllRules();

        assertFlowStorageSlotsInInitialState();
    }

    //  ============ Call flow  ============

    function test_sphereXValidateInternalPre_allowed_cf() public activateRule(CF) {
        allowed_cf_storage = [int256(1), -1];
        addAllowedPattern();

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }

        assertFlowStorageSlotsInInitialState();
    }

    function test_sphereXValidateInternalPre_not_allowed_cf() public activateRule(CF) {
        sendInternalNumberToEngine(1);

        vm.expectRevert(bytes("SphereX error: disallowed tx pattern"));
        sendInternalNumberToEngine(-1);
    }

    function test_sphereXValidatePrePost_allowed_cf() public activateRule(CF) {
        allowed_cf_storage = [int256(1), -1];
        addAllowedPattern();

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            if (allowed_cf_storage[i] > 0) {
                bytes memory empty;
                spherex_engine.sphereXValidatePre(allowed_cf_storage[i], address(0), empty);
            }
            if (allowed_cf_storage[i] < 0) {
                bytes32[] memory empty;
                spherex_engine.sphereXValidatePost(allowed_cf_storage[i], 0, empty, empty);
            }
        }

        assertFlowStorageSlotsInInitialState();
    }

    function test_sphereXValidatePrePost_not_allowed_cf() public activateRule(CF) {
        bytes memory empty;
        spherex_engine.sphereXValidatePre(1, address(0), empty);

        vm.expectRevert(bytes("SphereX error: disallowed tx pattern"));

        bytes32[] memory empty2;
        spherex_engine.sphereXValidatePost(-1, 0, empty2, empty2);
    }

    // allowed call flow is [1,2,3,4,5,-5,-4,-3,-2,-1]
    // we check success with [1,2,3,4,5,-5,-4,-3,-2,-1]
    function test_CallFlow_sanity() public activateRule(CF) {
        allowed_cf_storage = [int256(1), 2, 3, 4, 5, -5, -4, -3, -2, -1];
        addAllowedPattern();

        int256[10] memory allowed_long_cf = [int256(1), 2, 3, 4, 5, -5, -4, -3, -2, -1];
        for (uint256 i = 0; i < allowed_long_cf.length; i++) {
            sendInternalNumberToEngine(allowed_long_cf[i]);
        }

        assertFlowStorageSlotsInInitialState();
    }

    // allowed call flow is [1,-1]
    // we check success with [1,-1], [1,-1]
    function test_CallFlow_same_flow_twice_in_a_row() public activateRule(CF) {
        allowed_cf_storage = [int256(1), -1];
        addAllowedPattern();

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }

        assertFlowStorageSlotsInInitialState();
    }

    function test_currentPattern_and_callDepth_values_in_storage() public activateRule(CF) {
        allowed_cf_storage = [int256(1), -1];
        addAllowedPattern();

        sendInternalNumberToEngine(1);
        assertEq(getCurrentPattern(), uint216(bytes27(keccak256(abi.encode(int256(1), uint256(1))))));
        assertEq(getCurrentCallDepth(), uint256(2));

        sendInternalNumberToEngine(-1);
        assertFlowStorageSlotsInInitialState();
    }

    //  ============ Prefix tx flow  ============

    // Check that the current pattern isnt cleared at depth == 1 like in CF
    function test_PrefixTFlow_current_pattern_not_clean_at_depth_1() public activateRule(PREFIX_TX_FLOW) {
        allowed_cf_storage = [int256(1), -1];
        addAllowedPattern();

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }

        assertEq(getCurrentPattern() != uint216(1), true);
        assertEq(getCurrentCallDepth(), uint256(1));
    }

    // Sanity check, unlike cf the current pattern isnt being cleaned at depth==1 hence this
    // test should work and the entire [1,-1,2,-2] should be approved
    function test_PrefixTFlow_sanity() public activateRule(PREFIX_TX_FLOW) {
        allowed_cf_storage = [int256(1), -1];
        addAllowedPattern();

        allowed_cf_storage = [int256(1), -1, 2, -2];
        addAllowedPattern();

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }
    }

    // Check that after the block number is incremented we check the current flow from the beginning
    // In cf this test would have failed since the pattern would have been cleaned
    function test_PrefixTFlow_same_origin_same_block_number() public activateRule(PREFIX_TX_FLOW) {
        allowed_cf_storage = [int256(1), -1];
        addAllowedPattern();

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            if (i == allowed_cf_storage.length - 1) {
                vm.expectRevert("SphereX error: disallowed tx pattern");
            }
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }
    }

    // Check that after the block number is incremented we check the current flow from the begning
    function test_PrefixTFlow_same_origin_different_block_number() public activateRule(PREFIX_TX_FLOW) {
        allowed_cf_storage = [int256(1), -1];
        addAllowedPattern();

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }

        vm.roll(2);

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }
    }

    // Check that after the a different tx.origin we check the current flow from the begining
    function test_PrefixTFlow_different_origin_same_block_number() public activateRule(PREFIX_TX_FLOW) {
        allowed_cf_storage = [int256(1), -1];
        addAllowedPattern();

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }

        vm.startPrank(address(this), random_address);

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }
        vm.stopPrank();
    }

    function test_activateRule1_after_Rule2() public activateRule(PREFIX_TX_FLOW) {
        spherex_engine.configureRules(CF);
        allowed_cf_storage = [int256(1), -1];
        addAllowedPattern();

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }

        // If we were still in rule2 (prefix tx flow) this would have been reverted
        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }
    }

    function test_activateRule2_after_Rule1() public activateRule(CF) {
        spherex_engine.configureRules(PREFIX_TX_FLOW);

        // If we would have stayed in rule1 the test would have failed (see somment above the original test)
        test_PrefixTFlow_same_origin_same_block_number();
    }

    // Check currentBlock and currentAddress state variable change
    function test_PrefixTFlow_different_origin_different_block_number() public activateRule(PREFIX_TX_FLOW) {
        allowed_cf_storage = [int256(1), -1];
        addAllowedPattern();

        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }

        vm.roll(2);
        vm.startPrank(address(this), random_address);

        // since the effect on the storage will be applied only at the next transaction we need to call the engine at least
        // once again
        sendInternalNumberToEngine(allowed_cf_storage[0]);

        vm.stopPrank();

        // the slot layout is 0x[32 empty bits][160 bits for origin address][64 bits for block number]
        assertEq(
            getCurrentBlockBoundry(),
            bytes2(keccak256(abi.encode(2, random_address, block.timestamp, block.difficulty)))
        );
    }

    // Check that after we recognize a new transaction we dont allow the suffix of an approved flow
    // to pass. [1,-1], [1,-1,2,-2] approved, [2,-2] reverted!
    function test_PrefixTFlow_check_suffix() public activateRule(PREFIX_TX_FLOW) {
        allowed_cf_storage = [int256(1), -1];
        addAllowedPattern();

        allowed_cf_storage = [int256(1), -1, 2, -2];
        addAllowedPattern();

        allowed_cf_storage = [int256(1), -1];
        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }

        vm.roll(2);

        allowed_cf_storage = [int256(2), -2];
        for (uint256 i = 0; i < allowed_cf_storage.length; i++) {
            if (i == allowed_cf_storage.length - 1) {
                vm.expectRevert("SphereX error: disallowed tx pattern");
            }
            sendInternalNumberToEngine(allowed_cf_storage[i]);
        }
    }

    //  ============ Prefix tx/cf flow  ============

    // allowed call flow is [1,2,3,4,5,-5,-4,-3,-2,-1]
    // we check failure with [4,3,5,-5,-3,-4]
    function test_CallFlow_partial_elements_different_length(bytes8 rule) public activateRule(rule) {
        allowed_cf_storage = [int256(1), 2, 3, 4, 5, -5, -4, -3, -2, -1];
        addAllowedPattern();

        int256[6] memory not_allowed_cf = [int256(4), 3, 5, -5, -3, -4];
        for (uint256 i = 0; i < not_allowed_cf.length; i++) {
            if (i == not_allowed_cf.length - 1) {
                vm.expectRevert("SphereX error: disallowed tx pattern");
            }
            sendInternalNumberToEngine(not_allowed_cf[i]);
        }
    }

    // allowed call flow is [1,2,3,4,5,-5,-4,-3,-2,-1]
    // we check failure with [1,2,3,1,2,3,-3,-2,-1,-3,-2,-1]
    function test_CallFlow_partial_elements_same_length(bytes8 rule) public activateRule(rule) {
        allowed_cf_storage = [int256(1), 2, 3, 4, 5, -5, -4, -3, -2, -1];
        addAllowedPattern();

        int256[12] memory not_allowed_cf = [int256(1), 2, 3, 1, 2, 3, -3, -2, -1, -3, -2, -1];
        for (uint256 i = 0; i < not_allowed_cf.length; i++) {
            if (i == not_allowed_cf.length - 1) {
                vm.expectRevert("SphereX error: disallowed tx pattern");
            }
            sendInternalNumberToEngine(not_allowed_cf[i]);
        }
    }

    // allowed call flow is [1,2,3,4,5,-5,-4,-3,-2,-1]
    // we check failure with [1,2,4,5,-5,-4,-2,-1]
    function test_CallFlow_partial_elements_same_order_different_length(bytes8 rule) public activateRule(rule) {
        allowed_cf_storage = [int256(1), 2, 3, 4, 5, -5, -4, -3, -2, -1];
        addAllowedPattern();

        int256[8] memory not_allowed_cf = [int256(1), 2, 4, 5, -5, -4, -2, -1];
        for (uint256 i = 0; i < not_allowed_cf.length; i++) {
            if (i == not_allowed_cf.length - 1) {
                vm.expectRevert("SphereX error: disallowed tx pattern");
            }
            sendInternalNumberToEngine(not_allowed_cf[i]);
        }
    }

    // allowed call flow is [1,2,3,4,5,-5,-4,-3,-2,-1]
    // we check failure with [5,4,3,2,1,-1,-2,-3,-4,-5]
    function test_CallFlow_same_elements_backwards_order_same_length(bytes8 rule) public activateRule(rule) {
        allowed_cf_storage = [int256(1), 2, 3, 4, 5, -5, -4, -3, -2, -1];
        addAllowedPattern();

        int256[10] memory not_allowed_cf = [int256(5), 4, 3, 2, 1, -1, -2, -3, -4, -5];
        for (uint256 i = 0; i < not_allowed_cf.length; i++) {
            if (i == not_allowed_cf.length - 1) {
                vm.expectRevert("SphereX error: disallowed tx pattern");
            }
            sendInternalNumberToEngine(not_allowed_cf[i]);
        }
    }

    // allowed call flow is [1,2,3,4,5,-5,-4,-3,-2,-1]
    // we check failure with [2,1,5,3,4,-4,-3,-5,-1,-2]
    function test_CallFlow_same_elements_different_order_same_length(bytes8 rule) public activateRule(rule) {
        allowed_cf_storage = [int256(1), 2, 3, 4, 5, -5, -4, -3, -2, -1];
        addAllowedPattern();

        int256[10] memory not_allowed_cf = [int256(2), 1, 5, 3, 4, -4, -3, -5, -1, -2];
        for (uint256 i = 0; i < not_allowed_cf.length; i++) {
            if (i == not_allowed_cf.length - 1) {
                vm.expectRevert("SphereX error: disallowed tx pattern");
            }
            sendInternalNumberToEngine(not_allowed_cf[i]);
        }
    }

    // allowed call flow is [1,2,3,4,5,-5,-4,-3,-2,-1]
    // we check failure with [1,2,4,3,5,-5,-3,-4,-2,-1]
    function test_CallFlow_same_elements_different_order_same_length_same_prefix_and_suffix(bytes8 rule)
        public
        activateRule(rule)
    {
        allowed_cf_storage = [int256(1), 2, 3, 4, 5, -5, -4, -3, -2, -1];
        addAllowedPattern();

        int256[10] memory not_allowed_cf = [int256(1), 2, 4, 3, 5, -5, -3, -4, -2, -1];
        for (uint256 i = 0; i < not_allowed_cf.length; i++) {
            if (i == not_allowed_cf.length - 1) {
                vm.expectRevert("SphereX error: disallowed tx pattern");
            }
            sendInternalNumberToEngine(not_allowed_cf[i]);
        }
    }

    // allowed call flow is [1,2,3,4,5,-5,-4,-3,-2,-1]
    // we check success with [1,-1,2,-2,3,-3,4,-4,5,-5]
    function test_CallFlow_same_elements_different_nesting(bytes8 rule) public activateRule(rule) {
        allowed_cf_storage = [int256(1), 2, 3, 4, 5, -5, -4, -3, -2, -1];
        addAllowedPattern();

        int256[10] memory not_allowed_cf = [int256(1), -1, 2, -2, 3, -3, 4, -4, 5, -5];
        for (uint256 i = 0; i < not_allowed_cf.length; i++) {
            if (i == 1) {
                // we expect the -1 step will revert
                vm.expectRevert("SphereX error: disallowed tx pattern");
            }
            sendInternalNumberToEngine(not_allowed_cf[i]);
        }
    }

    // allowed call flow is [1,-1][2,-2]
    // we check success with [1,2,-2,-1]
    function test_CallFlow_same_elements_different_nesting_2(bytes8 rule) public activateRule(rule) {
        allowed_cf_storage = [int256(1), -1];
        addAllowedPattern();
        allowed_cf_storage = [int256(2), -2];
        addAllowedPattern();

        int256[4] memory not_allowed_cf = [int256(1), int256(2), -2, -1];
        for (uint256 i = 0; i < not_allowed_cf.length; i++) {
            if (i == not_allowed_cf.length - 1) {
                vm.expectRevert("SphereX error: disallowed tx pattern");
            }
            sendInternalNumberToEngine(not_allowed_cf[i]);
        }
    }

    function test_CFNumIsZero(bytes8 rule) public activateRule(rule) {
        vm.expectRevert(bytes("SphereX error: expected negative num"));
        sendInternalNumberToEngine(0);
    }

    function test_CFNumIsZero_in_the_middle_of_a_flow(bytes8 rule) public activateRule(rule) {
        allowed_cf_storage = [int256(1), 2, 3, 4, 5, -5, -4, -3, -2, -1];
        addAllowedPattern();

        int256[4] memory not_allowed_cf = [int256(1), 2, 3, 0];
        for (uint256 i = 0; i < not_allowed_cf.length; i++) {
            if (i == 3) {
                // we expect the 0 step will revert
                vm.expectRevert("SphereX error: expected negative num");
            }
            sendInternalNumberToEngine(not_allowed_cf[i]);
        }
    }

    function test_check_only_on_depth_zero(bytes8 rule) public activateRule(rule) {
        spherex_engine.setFlowCheckOnZeroDepth(true);
        allowed_cf_storage = [int256(1),2,-2, -1];
        addAllowedPattern();

        sendExternalNumberToEngine(1);
        sendExternalNumberToEngine(2);
        sendExternalNumberToEngine(-2);
        sendExternalNumberToEngine(-1);
        vm.roll(200);
        spherex_engine.setFlowCheckOnZeroDepth(false);

        sendExternalNumberToEngine(1);
        sendExternalNumberToEngine(2);
        vm.expectRevert("SphereX error: disallowed tx pattern");
        sendExternalNumberToEngine(-2);
    }
    function test_check_only_on_depth_zero_2_cf() public activateRule(CF) {
        spherex_engine.setFlowCheckOnZeroDepth(true);
        allowed_cf_storage = [int256(1),2,-2, -1];
        addAllowedPattern();
        allowed_cf_storage = [int256(3),-3];
        addAllowedPattern();
        
        sendExternalNumberToEngine(1);
        sendExternalNumberToEngine(2);
        sendExternalNumberToEngine(-2);
        sendExternalNumberToEngine(-1);
        sendExternalNumberToEngine(3);
        sendExternalNumberToEngine(-3);
        sendExternalNumberToEngine(4);
        vm.expectRevert("SphereX error: disallowed tx pattern");
        sendExternalNumberToEngine(-4);
    }
}
