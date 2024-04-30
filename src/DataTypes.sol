enum Operation {
    USE,
    ENABLE
}

library SigDecode {
    function packSelection(Operation operation, address validator, uint256 nonce)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(operation, validator, nonce);
    }

    function unpackSelection(bytes calldata data)
        internal
        pure
        returns (Operation operation, address validator, uint256 nonce)
    {
        operation = Operation(uint8(bytes1(data[:1])));
        validator = address(bytes20(data[1:21]));
        nonce = uint256(bytes32(data[21:53]));
    }

    function unpackEnable(bytes calldata data)
        internal
        returns (bytes calldata validatorData, bytes calldata validatorSig, bytes calldata authSig)
    {
        assembly {
            let offset := data.offset
            let baseOffset := offset
            let dataPointer := add(offset, calldataload(offset))
            validatorData.offset := add(dataPointer, 32)
            validatorData.length := calldataload(dataPointer)
            offset := add(offset, 32)

            dataPointer := add(baseOffset, calldataload(offset))
            validatorSig.offset := add(dataPointer, 32)
            validatorSig.length := calldataload(dataPointer)
            offset := add(offset, 32)

            dataPointer := add(baseOffset, calldataload(offset))
            authSig.offset := add(dataPointer, 32)
            authSig.length := calldataload(dataPointer)
        }
    }

    function unpackUse(bytes calldata data) internal returns (bytes calldata validatorSig, bytes calldata authSig) {
        assembly {
            let offset := data.offset
            let baseOffset := offset
            let dataPointer := add(offset, calldataload(offset))

            dataPointer := add(baseOffset, calldataload(offset))
            validatorSig.offset := add(dataPointer, 32)
            validatorSig.length := calldataload(dataPointer)
            offset := add(offset, 32)

            dataPointer := add(baseOffset, calldataload(offset))
            authSig.offset := add(dataPointer, 32)
            authSig.length := calldataload(dataPointer)
        }
    }
}
