// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./lib/ModeLib.sol";
import "./lib/ExecutionLib.sol";
import { MultiSendAuthCallOnly } from "./utils/MultiSendAuthCallOnly.sol";

contract ExecutionHelper {
    using ModeLib for ModeCode;
    using ExecutionLib for bytes;

    error InvalidMode();
    error ExecutionFailed();

    function _authCall(address to, uint256 value, bytes memory data) internal returns (bool) {
        bool success;
        uint256 length = data.length;
        assembly {
            success := authcall(gas(), to, value, 0, data, length, 0, 0)
        }
        if (!success) revert ExecutionFailed();
    }

    function _execute(ModeCode mode, bytes calldata executionCalldata) internal {
        (CallType _calltype, ExecType _execType, ModeSelector _modeSelector, ModePayload _modePayload) = mode.decode();
        if (_modeSelector != MODE_EIP3074) revert InvalidMode();

        if (_calltype == CALLTYPE_SINGLE) {
            (address to, uint256 value, bytes calldata callData) = executionCalldata.decodeSingle();
            _authCall(to, value, callData);
        }
    }
}
