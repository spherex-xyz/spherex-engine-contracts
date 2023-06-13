// SPDX-License-Identifier: UNLICENSED
// (c) SphereX 2023 Terms&Conditions

pragma solidity ^0.8.17;

import {
    AccessControlDefaultAdminRules, IERC165
} from "openzeppelin-contracts/access/AccessControlDefaultAdminRules.sol";
import {ISphereXEngine} from "./ISphereXEngine.sol";

/**
 * @title SphereX Engine
 * @notice Gathers information about an ongoing transaction and reverts if it seems malicious
 */
contract SphereXEngine is ISphereXEngine, AccessControlDefaultAdminRules {
    bytes8 private _engineRules; // By default the contract will be deployed with no guarding rules activated
    mapping(address => ConfigurationInfo) private _allowedSenders;
    mapping(uint256 => ConfigurationInfo) private _allowedPatterns;

    // We initialize the next variables to 1 and not 0 to save gas costs on future transactions
    uint256 private _currentPattern = PATTERN_START;
    uint256 private _callDepth = DEPTH_START;

    // Represent keccak256(abi.encode(block.number, tx.origin))
    bytes32 private _currentBlockOriginHash = bytes32(uint256(1));

    uint256 private constant PATTERN_START = 1;
    uint256 private constant DEPTH_START = 1;
    bytes32 private constant DEACTIVATED = bytes32(0);
    uint64 private constant Rules1And2Together = 3;

    event TxStartedAtIrregularDepth();

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    struct ConfigurationInfo {
        bool isPermited;
        uint128 timestamp;
    }

    constructor() AccessControlDefaultAdminRules(1 days, msg.sender) {
        grantRole(OPERATOR_ROLE, msg.sender);
    }

    modifier onlyOperator() {
        require(hasRole(OPERATOR_ROLE, msg.sender), "SphereX error: operator required");
        _;
    }

    event ConfigureRules(bytes8 oldRules, bytes8 newRules);
    event DisableAllRules(bytes8 oldRules);
    event AddedAllowedSender(address sender);
    event RemovedAllowedSender(address sender);
    event AddedAllowedPattern(uint256 pattern);
    event RemovedAllowedPattern(uint256 pattern);

    modifier returnsIfNotActivated() {
        if (_engineRules == DEACTIVATED) {
            return;
        }

        _;
    }

    modifier onlyApprovedSenders() {
        ConfigurationInfo memory configInfo = _allowedSenders[msg.sender];
        if (!configInfo.isPermited) {
            // if the change was made in the same timestamp then we dont want to revert,
            // otherwise we should revert.
            require(configInfo.timestamp == block.timestamp, "SphereX error: disallowed sender");
        }
        _;
    }

    // ============ Management ============

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AccessControlDefaultAdminRules, IERC165)
        returns (bool)
    {
        return interfaceId == type(ISphereXEngine).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * Activate the guardian rules
     * @param rules bytes8 representing the new rules to activate.
     */
    function configureRules(bytes8 rules) external onlyOperator {
        require(Rules1And2Together & uint64(rules) != Rules1And2Together, "SphereX error: illegal rules combination");
        bytes8 oldRules = _engineRules;
        _engineRules = rules;
        emit ConfigureRules(oldRules, _engineRules);
    }

    /**
     * Deactivates the engine, the calls will return without being checked
     */
    function deactivateAllRules() external onlyOperator {
        bytes8 oldRules = _engineRules;
        _engineRules = bytes8(uint64(0));
        emit DisableAllRules(oldRules);
    }

    /**
     * Adds addresses that will be served by this engine. An address that was never added will get a revert if it tries to call the engine.
     * @param senders list of address to add to the set of allowed addresses
     */
    function addAllowedSender(address[] calldata senders) external onlyOperator {
        for (uint256 i = 0; i < senders.length; ++i) {
            _allowedSenders[senders[i]] = ConfigurationInfo(true, 0);
            emit AddedAllowedSender(senders[i]);
        }
    }

    /**
     * Removes address so that they will not get served when calling the engine. Transaction from these addresses will get reverted.
     * @param senders list of address to stop service.
     */
    function removeAllowedSender(address[] calldata senders) external onlyOperator {
        for (uint256 i = 0; i < senders.length; ++i) {
            _allowedSenders[senders[i]] = ConfigurationInfo(false, uint128(block.timestamp));
            emit RemovedAllowedSender(senders[i]);
        }
    }

    /**
     * Add allowed patterns - these are representation of allowed flows of transactions, and prefixes of these flows
     * @param patterns list of flows to allow as valid and non-malicious flows
     */
    function addAllowedPatterns(uint256[] calldata patterns) external onlyOperator {
        for (uint256 i = 0; i < patterns.length; ++i) {
            _allowedPatterns[patterns[i]] = ConfigurationInfo(true, 0);
            emit AddedAllowedPattern(patterns[i]);
        }
    }

    /**
     * Remove allowed patterns - these are representation flows of transactions, and prefixes of these flows,
     * that are no longer considered valid and benign
     * @param patterns list of flows that no longer considered valid and non-malicious
     */
    function removeAllowedPatterns(uint256[] calldata patterns) external onlyOperator {
        for (uint256 i = 0; i < patterns.length; ++i) {
            _allowedPatterns[patterns[i]] = ConfigurationInfo(false, uint128(block.timestamp));
            emit RemovedAllowedPattern(patterns[i]);
        }
    }

    // ============ CF ============

    /**
     * Checks if rule1 is activated.
     */
    function _isRule1Activated() private view returns (bool) {
        return (_engineRules & bytes8(uint64(1))) > 0;
    }

    /**
     * update the current CF pattern with a new positive number (signifying function entry),
     * @param num element to add to the flow.
     */
    function _addCfElementFunctionEntry(int256 num) private {
        require(num > 0, "SphereX error: expected positive num");
        uint256 callDepth = _callDepth;
        uint256 currentPattern = _currentPattern;

        // Upon entry to a new function if we are configured to PrefixTxFlow we should check if we are at the same transaction
        // or a new one. in case of a new one we need to reinit the currentPattern, and save
        // the new transaction "hash" (block.number+tx.origin)
        bytes32 currentBlockOriginHash =
            keccak256(abi.encode(block.number, tx.origin, block.timestamp, block.difficulty));
        if (currentBlockOriginHash != _currentBlockOriginHash) {
            currentPattern = PATTERN_START;
            _currentBlockOriginHash = currentBlockOriginHash;
            if (callDepth != DEPTH_START) {
                // This is an edge case we (and the client) should be able to monitor easily.
                emit TxStartedAtIrregularDepth();
                callDepth = DEPTH_START;
            }
        }

        currentPattern = uint256(keccak256(abi.encode(num, currentPattern)));
        ++callDepth;

        _callDepth = callDepth;
        _currentPattern = currentPattern;
    }

    /**
     * update the current CF pattern with a new negative number (signfying function exit),
     * under some conditions, this will also check the validity of the pattern.
     * @param num element to add to the flow. should be negative.
     * @param forceCheck force the check of the current pattern, even if normal test conditions don't exist.
     */
    function _addCfElementFunctionExit(int256 num, bool forceCheck) private {
        require(num < 0, "SphereX error: expected negative num");
        uint256 callDepth = _callDepth;
        uint256 currentPattern = _currentPattern;

        currentPattern = uint256(keccak256(abi.encode(num, currentPattern)));
        --callDepth;

        if ((forceCheck) || (callDepth == DEPTH_START)) {
            _checkCallFlow(currentPattern);
        }

        // If we are configured to CF then if we reach depth == DEPTH_START we should reinit the
        // currentPattern
        if (callDepth == DEPTH_START && _isRule1Activated()) {
            currentPattern = PATTERN_START;
        }

        _callDepth = callDepth;
        _currentPattern = currentPattern;
    }

    /**
     * Check if the current call flow pattern (that is, the result of the rolling hash) is an allowed pattern.
     */
    function _checkCallFlow(uint256 currentPattern) private view {
        ConfigurationInfo memory configInfo = _allowedPatterns[currentPattern];
        // if the change was made in the same timestamp then we dont want to revert,
        // otherwise we should revert.
        if (!configInfo.isPermited) {
            require(configInfo.timestamp == block.timestamp, "SphereX error: disallowed tx pattern");
        }
    }

    /**
     * This is the function that is actually called by the modifier of the protected contract before the body of the function.
     * This is used only for external call functions.
     * @param num id of function to add. Should be positive
     * @param sender For future use
     * @param data For future use
     * @return result in the future will return instruction on what storage slots to gather, but not used for now
     */
    function sphereXValidatePre(int256 num, address sender, bytes calldata data)
        external
        override
        returnsIfNotActivated // may return empty bytes32[]
        onlyApprovedSenders
        returns (bytes32[] memory result)
    {
        _addCfElementFunctionEntry(num);
        return result;
    }

    /**
     * This is the function that is actually called by the modifier of the protected contract after the body of the function.
     * This is used only for external call functions (that is, external, and public when called outside the contract).
     * @param num id of function to add. Should be negative
     * @param valuesBefore For future use
     * @param valuesAfter For future use
     */
    function sphereXValidatePost(
        int256 num,
        uint256 gas,
        bytes32[] calldata valuesBefore,
        bytes32[] calldata valuesAfter
    ) external override returnsIfNotActivated onlyApprovedSenders {
        _addCfElementFunctionExit(num, true);
    }

    /**
     * This is the function that is actually called by the modifier of the protected contract before and after the body of the function.
     * This is used only for internal function calls (internal and private functions).
     * @param num id of function to add.
     */
    function sphereXValidateInternalPre(int256 num) external override returnsIfNotActivated onlyApprovedSenders {
        _addCfElementFunctionEntry(num);
    }

    /**
     * This is the function that is actually called by the modifier of the protected contract before and after the body of the function.
     * This is used only for internal function calls (internal and private functions).
     * @param num id of function to add.
     */
    function sphereXValidateInternalPost(int256 num, uint256 gas)
        external
        override
        returnsIfNotActivated
        onlyApprovedSenders
    {
        _addCfElementFunctionExit(num, false);
    }
}
