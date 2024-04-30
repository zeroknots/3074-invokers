pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/interfaces/PackedUserOperation.sol";

import "src/EIP3074ERC7579Account.sol";
import "src/utils/MockValidator.sol";
import "src/lib/ModeLib.sol";
import { EntryPointLib } from "../src/utils/erc4337Util.sol";

contract DC {
    function dc(address target, bytes calldata callData) external {
        console.log("dc");
        target.delegatecall(callData);
    }
}

contract ERC7579Test is Test {
    address owner;
    uint256 ownerKey;
    IEntryPoint public ep;
    address payable bundler;

    EIP3074ERC7579Account account;
    MockValidator mockValidator;
    uint8 AUTHCALL_IDENTIFIER = 2;

    DC dc;

    function target() external {
        console.log("target");
    }

    function setUp() external {
        ep = IEntryPoint(EntryPointLib.deploy());
        dc = new DC();
        (owner, ownerKey) = makeAddrAndKey("Owner");
        account = new EIP3074ERC7579Account(ep);
        mockValidator = new MockValidator();
        bundler = payable(makeAddr("Bundler"));
    }

    function testSign() external {
        vm.deal(address(account), 1e18);
        vm.deal(address(owner), 2);
        console.log("Owner :", owner);
        bytes32 digest = account.getDigest(keccak256(abi.encodePacked(mockValidator, hex"deadbeef")), 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        address to = address(dc);
        bytes memory data = abi.encodeCall(DC.dc, (address(1), hex""));
        uint256 value = 0;

        ModeCode mode = ModeLib.encode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT, MODE_EIP3074, ModePayload.wrap(bytes22(0)));
        bytes memory executionData = ExecutionLib.encodeSingle(to, value, data);

        PackedUserOperation memory op = PackedUserOperation({
            sender: address(account),
            nonce: uint256(bytes32(bytes20(address(owner)))),
            initCode: hex"",
            callData: abi.encodePacked(
                account.executeUserOp.selector,
                // abi.encodePacked(AUTHCALL_IDENTIFIER, address(to), uint256(value), data.length, data)
                abi.encodePacked(IERC7579Account.execute.selector, mode, executionData)
            ),
            paymasterAndData: hex"",
            gasFees: bytes32(0),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            signature: abi.encodePacked(
                Operation.ENABLE,
                address(mockValidator),
                uint256(0),
                abi.encode(hex"deadbeef", hex"cafecafe", abi.encodePacked(r, s, v))
            )
        });
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        ep.handleOps(ops, bundler);
        require(to.balance == 1);
    }
}
