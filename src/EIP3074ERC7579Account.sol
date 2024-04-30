// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Auth } from "./utils/Auth.sol";
import { PackedUserOperation } from "./interfaces/PackedUserOperation.sol";
import { IValidator, IModule, IStatelessValidator } from "./interfaces/IERC7579Modules.sol";
import { IERC7579Account } from "./interfaces/IERC7579Account.sol";
import { IEntryPoint } from "./interfaces/IEntryPoint.sol";
import { SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";
import "./lib/ModeLib.sol";
import "./lib/ExecutionLib.sol";
import "forge-std/console.sol";
import "./utils/utils.sol";
import "./DataTypes.sol";
import { MultiSendAuthCallOnly } from "./utils/MultiSendAuthCallOnly.sol";
import "forge-std/console2.sol";
import "./ExecutionHelper.sol";
/*
    TODO
    - add storage support 
        - differentiate enable mode/non-enable mode
    - add hook support
    - add policy/signer support
    - merge with https://github.com/thogard785/generalized-interpretable-invoker/tree/main to serve the same role
    - add staking support
    Optional
    - add pre-deposit wrapped ETH?
 */

// @notice THIS IS EXPERIMENTAL, DO NOT USE THIS FOR PROD
// @dev NOTE : this is vulnerable to DoS since actual validation for userOpHash is done on the execution side, figuring out the fixes though
contract EIP3074ERC7579Account is Auth, ExecutionHelper {
    using ExecutionLib for bytes;
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;
    using SigDecode for bytes;

    struct ValidatorData {
        bytes data;
    }

    SentinelList4337Lib.SentinelList internal $validators;
    mapping(address validatorModule => mapping(address account => ValidatorData data)) $validatorData;

    IEntryPoint public immutable ep;

    error OutOfTimeRange();

    constructor(IEntryPoint _ep) {
        ep = _ep;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256)
    {
        require(msg.sender == address(ep), "!ep");
        address eoa;
        uint256 nonce = userOp.nonce;
        assembly {
            eoa := shr(96, nonce)
        }
        Operation operation;
        address validator;
        (operation, validator, nonce) = userOp.signature.unpackSelection();
        bytes memory validatorData;
        bytes calldata validatorSig;
        bytes calldata authSig;

        if (operation == Operation.USE) {
            (validatorSig, authSig) = SigDecode.unpackUse(userOp.signature[53:]);
            validatorData = $validatorData[validator][eoa].data;
        } else if (operation == Operation.ENABLE) {
            (validatorData, validatorSig, authSig) = SigDecode.unpackEnable(userOp.signature[53:]);
            // enable validator module for account
            $validators.init({ account: eoa });
            $validators.push({ account: eoa, newEntry: validator });
            $validatorData[validator][eoa] = ValidatorData({ data: validatorData });
        } else {
            revert();
        }

        return _validate({
            eoa: eoa,
            validator: validator,
            validatorData: validatorData,
            validationSig: validatorSig,
            authSig: authSig,
            nonce: nonce
        });
    }

    function _validate(
        address eoa,
        address validator,
        bytes memory validatorData,
        bytes calldata validationSig,
        bytes calldata authSig,
        uint256 nonce
    ) internal returns (uint256 validationData) {
        bytes32 commit = keccak256(abi.encodePacked(validator, validatorData));
        address signer = ecrecover(
            getDigest(commit, nonce), uint8(bytes1(authSig[64])), bytes32(authSig[0:32]), bytes32(authSig[32:64])
        );
        if (eoa != signer) return 1;
        bool success = IStatelessValidator(validator).validateSignatureWithData({
            hash: keccak256(abi.encodePacked(validationData)),
            signature: validationSig,
            data: validatorData
        });
        return success ? 0 : 1;
    }

    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external {
        require(msg.sender == address(ep), "!ep");
        address eoa;
        address validator = address(bytes20(userOp.signature[1:21]));
        uint256 nonce = userOp.nonce;
        assembly {
            eoa := shr(96, nonce)
        }

        (, bytes calldata validatorSig, bytes calldata authSig) = SigDecode.unpackEnable(userOp.signature[53:]);
        bytes memory validatorData = $validatorData[validator][eoa].data;

        // do auth
        doAuth(eoa, validator, validatorData, authSig);

        // NOTE : userOp.sender will remain as invoker, let's keep this in mind
        PackedUserOperation memory op = userOp;
        op.signature = validatorSig;

        // doExecute(userOp.callData[4:]);

        bytes4 accountSig = bytes4(userOp.callData[4:8]);

        if (accountSig == IERC7579Account.execute.selector) {
            // (CallType _calltype, ExecType _execType, ModeSelector _modeSelector, ModePayload _modePayload) =
            //     ModeLib.decode();
            _execute(ModeCode.wrap(bytes32(userOp.callData[8:40])), userOp.callData[40:]);
        }
    }

    function doAuth(address eoa, address validator, bytes memory validatorData, bytes calldata authSig) internal {
        bytes32 commit = keccak256(abi.encodePacked(validator, validatorData));
        Signature memory sig = Signature({
            signer: eoa,
            yParity: vToYParity(uint8(bytes1(authSig[64]))),
            r: bytes32(authSig[0:32]),
            s: bytes32(authSig[32:64])
        });
        bool success = auth(commit, sig);
        require(success, "Auth failed");
    }

    function doEnable(address eoa, address validator, bytes calldata validatorData) internal {
        $validators.push({ account: eoa, newEntry: validator });
        $validatorData[validator][eoa] = ValidatorData({ data: validatorData });
    }

    function doValidation(address validator, PackedUserOperation memory op, bytes32 userOpHash)
        internal
        returns (uint256)
    {
        (bool success, bytes memory result) = authcall(
            validator, abi.encodeWithSelector(IValidator.validateUserOp.selector, op, userOpHash), 0, gasleft()
        );
        require(success, "Validation failed");
        return abi.decode(result, (uint256));
    }

    function doExecute(bytes calldata callData) internal {
        MultiSendAuthCallOnly.multiSend(callData);
    }

    function parseSig(bytes calldata sig)
        internal
        pure
        returns (bytes calldata validatorData, bytes calldata validatorSig, bytes calldata authSig)
    {
        assembly {
            validatorData.offset := add(add(sig.offset, 84), calldataload(add(sig.offset, 52)))
            validatorData.length := calldataload(sub(validatorData.offset, 32))
            validatorSig.offset := add(add(sig.offset, 84), calldataload(add(sig.offset, 84)))
            validatorSig.length := calldataload(sub(validatorSig.offset, 32))
            authSig.offset := add(add(sig.offset, 84), calldataload(add(sig.offset, 116)))
            authSig.length := calldataload(sub(authSig.offset, 32))
        }
    }
}
