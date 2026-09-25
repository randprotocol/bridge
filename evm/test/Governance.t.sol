// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IRandBridge} from "../src/interfaces/IRandBridge.sol";
import {RandBridgeBase} from "../src/RandBridgeBase.sol";
import {EthereumRandBridge} from "../src/EthereumRandBridge.sol";
import {Governance} from "../script/Governance.s.sol";
import {GovernancePins} from "../script/GovernancePins.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// BR-3: the admin role of an EVM endpoint handed to an OpenZeppelin
/// `TimelockController` (48 h, proposers = executors = cancellers = the admin
/// multisig, no timelock admin), and the pauser to a separate multisig, all
/// through `script/Governance.s.sol`. The multisigs are plain addresses here:
/// the timelock only checks roles, not whether the holder is a Safe.
///
/// The fork variant runs the same handover against the live Ethereum and BSC
/// bridges, pranking (broadcasting as) the current admin EOA:
///
///   ETH_FORK_URL=... BSC_FORK_URL=... forge test --match-contract Governance
///
/// in the DEFAULT profile (paris), not `fork`: the timelock's runtime code hash is pinned
/// (`GovernancePins`) for the paris build, and a cancun build of it is refused by design. The
/// live bridge is paris code, so the default profile executes it as deployed.
contract GovernanceTest is Test {
    uint256 constant DELAY = 172_800;
    bytes32 constant SALT = keccak256("br3-accept-admin");

    Governance gov;
    RandBridgeBase bridge;
    MockERC20 token;

    address eoa = makeAddr("current-admin-eoa");
    address adminMs = makeAddr("admin-multisig");
    address pauseMs = makeAddr("pause-multisig");
    address stranger = makeAddr("stranger");

    function setUp() public {
        gov = new Governance();
        address[] memory guardians = new address[](1);
        guardians[0] = vm.addr(1);
        bridge = new EthereumRandBridge(eoa, eoa, keccak256("rand-emitter-test"), guardians);
        token = new MockERC20("USD Tether", "USDT", 6);
        _giveMultisigsCode();
    }

    /// The handover requires both multisigs to be contracts (Safes on mainnet); a STOP is enough
    /// here, the timelock and the bridge only look at msg.sender.
    function _giveMultisigsCode() internal {
        vm.etch(adminMs, hex"00");
        vm.etch(pauseMs, hex"00");
    }

    function _timelock(address[] memory proposers, address[] memory executors, address tlAdmin)
        internal
        returns (TimelockController)
    {
        return new TimelockController(DELAY, proposers, executors, tlAdmin);
    }

    function _one(address a) internal pure returns (address[] memory r) {
        r = new address[](1);
        r[0] = a;
    }

    function _two(address a, address b) internal pure returns (address[] memory r) {
        r = new address[](2);
        r[0] = a;
        r[1] = b;
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    /// Steps 1-3: deploy the timelock, then setPauser + transferAdmin from the EOA.
    function _deployAndHandOver(RandBridgeBase b, address from) internal returns (TimelockController tl) {
        tl = gov.deployTimelock(adminMs, DELAY);
        gov.handoverFrom(from, address(b), address(tl), adminMs, pauseMs);
    }

    function _schedule(TimelockController tl, address target, bytes memory data, bytes32 salt) internal {
        uint256 delay = tl.getMinDelay(); // read first: a call would consume the prank
        vm.prank(adminMs);
        tl.schedule(target, 0, data, bytes32(0), salt, delay);
    }

    function _execute(TimelockController tl, address target, bytes memory data, bytes32 salt) internal {
        vm.prank(adminMs);
        tl.execute(target, 0, data, bytes32(0), salt);
    }

    /// Steps 4-5 exactly as the Safe batches carry them.
    function _acceptThroughTimelock(RandBridgeBase b, TimelockController tl) internal {
        (bytes memory sch, bytes memory exe) = gov.acceptCalls(address(b), address(tl), SALT);
        vm.prank(adminMs);
        (bool ok,) = address(tl).call(sch);
        assertTrue(ok, "schedule acceptAdmin");
        vm.warp(block.timestamp + tl.getMinDelay());
        vm.prank(adminMs);
        (ok,) = address(tl).call(exe);
        assertTrue(ok, "execute acceptAdmin");
    }

    function _fullHandover() internal returns (TimelockController tl) {
        tl = _deployAndHandOver(bridge, eoa);
        _acceptThroughTimelock(bridge, tl);
    }

    function _readyOnly() internal pure returns (bytes32) {
        return bytes32(1 << uint8(TimelockController.OperationState.Ready));
    }

    // ------------------------------------------------------------------
    // end state
    // ------------------------------------------------------------------

    function test_handover_end_state() public {
        TimelockController tl = _fullHandover();
        assertEq(bridge.admin(), address(tl), "admin is the timelock");
        assertEq(bridge.pauser(), pauseMs, "pauser is the pause multisig");
        assertEq(bridge.pendingAdmin(), address(0), "no transfer outstanding");
    }

    function test_old_eoa_locked_out() public {
        _fullHandover();
        vm.startPrank(eoa);
        vm.expectRevert(IRandBridge.NotAdmin.selector);
        bridge.setToken(address(token), true, 0, 0);
        vm.expectRevert(IRandBridge.NotAdmin.selector);
        bridge.setProtocolFee(100);
        vm.expectRevert(IRandBridge.NotAdmin.selector);
        bridge.withdrawFees(address(token), eoa, 0);
        vm.expectRevert(IRandBridge.NotAdmin.selector);
        bridge.unpause();
        vm.expectRevert(IRandBridge.NotAdmin.selector);
        bridge.transferAdmin(eoa);
        vm.expectRevert(IRandBridge.NotAdmin.selector);
        bridge.setPauser(eoa);
        vm.stopPrank();
    }

    function test_the_multisig_itself_is_not_admin() public {
        _fullHandover();
        vm.prank(adminMs);
        vm.expectRevert(IRandBridge.NotAdmin.selector);
        bridge.setToken(address(token), true, 0, 0);
    }

    // ------------------------------------------------------------------
    // the timelock
    // ------------------------------------------------------------------

    function test_execute_before_min_delay_reverts_after_it_succeeds() public {
        TimelockController tl = _fullHandover();
        bytes memory data = abi.encodeCall(IRandBridge.setToken, (address(token), true, 0, 0));
        _schedule(tl, address(bridge), data, SALT);
        bytes32 id = tl.hashOperation(address(bridge), 0, data, bytes32(0), SALT);

        vm.warp(block.timestamp + DELAY - 1);
        vm.prank(adminMs);
        vm.expectRevert(
            abi.encodeWithSelector(TimelockController.TimelockUnexpectedOperationState.selector, id, _readyOnly())
        );
        tl.execute(address(bridge), 0, data, bytes32(0), SALT);

        vm.warp(block.timestamp + 1);
        _execute(tl, address(bridge), data, SALT);
        assertTrue(bridge.tokenConfig(address(token)).enabled, "setToken went through the timelock");
    }

    function test_non_proposer_cannot_schedule() public {
        TimelockController tl = _fullHandover();
        bytes memory data = abi.encodeCall(IRandBridge.setProtocolFee, (100));
        bytes32 role = tl.PROPOSER_ROLE();
        address[3] memory who = [eoa, pauseMs, stranger];
        for (uint256 i = 0; i < who.length; i++) {
            vm.prank(who[i]);
            vm.expectRevert(
                abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, who[i], role)
            );
            tl.schedule(address(bridge), 0, data, bytes32(0), SALT, DELAY);
        }
    }

    function test_non_executor_cannot_execute() public {
        TimelockController tl = _fullHandover();
        bytes memory data = abi.encodeCall(IRandBridge.setProtocolFee, (100));
        _schedule(tl, address(bridge), data, SALT);
        vm.warp(block.timestamp + DELAY);
        bytes32 role = tl.EXECUTOR_ROLE();
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, role)
        );
        tl.execute(address(bridge), 0, data, bytes32(0), SALT);
    }

    function test_admin_multisig_can_cancel_then_it_cannot_execute() public {
        TimelockController tl = _fullHandover();
        bytes memory data = abi.encodeCall(IRandBridge.setProtocolFee, (100));
        _schedule(tl, address(bridge), data, SALT);
        bytes32 id = tl.hashOperation(address(bridge), 0, data, bytes32(0), SALT);

        bytes32 role = tl.CANCELLER_ROLE();
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, role)
        );
        tl.cancel(id);

        vm.prank(adminMs);
        tl.cancel(id);
        assertFalse(tl.isOperation(id), "cancelled");

        vm.warp(block.timestamp + DELAY);
        vm.prank(adminMs);
        vm.expectRevert(
            abi.encodeWithSelector(TimelockController.TimelockUnexpectedOperationState.selector, id, _readyOnly())
        );
        tl.execute(address(bridge), 0, data, bytes32(0), SALT);
        assertEq(bridge.protocolFeeBps(), 10, "fee unchanged");
    }

    // ------------------------------------------------------------------
    // pause and unpause
    // ------------------------------------------------------------------

    function test_pause_multisig_pauses_immediately() public {
        _fullHandover();
        vm.prank(pauseMs);
        bridge.pause();
        assertTrue(bridge.paused(), "paused in the same block");

        vm.prank(eoa);
        vm.expectRevert(IRandBridge.NotPauser.selector);
        bridge.pause();
    }

    function test_unpause_only_through_the_timelock_after_the_delay() public {
        TimelockController tl = _fullHandover();
        vm.prank(pauseMs);
        bridge.pause();

        address[3] memory who = [pauseMs, adminMs, eoa];
        for (uint256 i = 0; i < who.length; i++) {
            vm.prank(who[i]);
            vm.expectRevert(IRandBridge.NotAdmin.selector);
            bridge.unpause();
        }

        bytes memory data = abi.encodeCall(IRandBridge.unpause, ());
        _schedule(tl, address(bridge), data, SALT);
        bytes32 id = tl.hashOperation(address(bridge), 0, data, bytes32(0), SALT);
        vm.warp(block.timestamp + DELAY - 1);
        vm.prank(adminMs);
        vm.expectRevert(
            abi.encodeWithSelector(TimelockController.TimelockUnexpectedOperationState.selector, id, _readyOnly())
        );
        tl.execute(address(bridge), 0, data, bytes32(0), SALT);
        assertTrue(bridge.paused(), "still paused inside the delay");

        vm.warp(block.timestamp + 1);
        _execute(tl, address(bridge), data, SALT);
        assertFalse(bridge.paused(), "unpaused through the timelock");
    }

    // ------------------------------------------------------------------
    // before acceptance
    // ------------------------------------------------------------------

    function test_until_acceptance_eoa_is_admin_and_can_cancel_the_handover() public {
        TimelockController tl = _deployAndHandOver(bridge, eoa);
        assertEq(bridge.admin(), eoa, "EOA is still admin");
        assertEq(bridge.pendingAdmin(), address(tl), "timelock pending");
        assertEq(bridge.pauser(), pauseMs, "pauser moved at once");

        vm.prank(eoa);
        bridge.setToken(address(token), true, 0, 0); // still works

        (bytes memory sch, bytes memory exe) = gov.acceptCalls(address(bridge), address(tl), SALT);
        vm.prank(adminMs);
        (bool ok,) = address(tl).call(sch);
        assertTrue(ok, "schedule");

        vm.prank(eoa);
        bridge.transferAdmin(address(0)); // cancel
        assertEq(bridge.pendingAdmin(), address(0));

        vm.warp(block.timestamp + DELAY);
        vm.prank(adminMs);
        (ok,) = address(tl).call(exe);
        assertFalse(ok, "acceptAdmin fails once cancelled");
        assertEq(bridge.admin(), eoa, "EOA keeps the role");
    }

    // ------------------------------------------------------------------
    // deployTimelock
    // ------------------------------------------------------------------

    function test_deployTimelock_roles_and_no_admin() public {
        TimelockController tl = gov.deployTimelock(adminMs, DELAY);
        assertEq(tl.getMinDelay(), DELAY);
        assertTrue(tl.hasRole(tl.PROPOSER_ROLE(), adminMs), "proposer");
        assertTrue(tl.hasRole(tl.EXECUTOR_ROLE(), adminMs), "executor");
        assertTrue(tl.hasRole(tl.CANCELLER_ROLE(), adminMs), "canceller");
        assertFalse(tl.hasRole(tl.EXECUTOR_ROLE(), address(0)), "execution is not open");
        assertFalse(tl.hasRole(tl.DEFAULT_ADMIN_ROLE(), adminMs), "multisig is not timelock admin");
        assertFalse(tl.hasRole(tl.DEFAULT_ADMIN_ROLE(), address(gov)), "script is not timelock admin");
        assertFalse(tl.hasRole(tl.DEFAULT_ADMIN_ROLE(), tx.origin), "broadcaster is not timelock admin");
        assertTrue(tl.hasRole(tl.DEFAULT_ADMIN_ROLE(), address(tl)), "only the timelock administers itself");
    }

    function test_deployTimelock_refuses_min_delay_under_a_day() public {
        vm.expectRevert(bytes("MIN_DELAY < 86400"));
        gov.deployTimelock(adminMs, 86_399);
        gov.deployTimelock(adminMs, 86_400); // the floor itself is allowed
    }

    function test_deployTimelock_refuses_zero_multisig() public {
        vm.expectRevert(bytes("ADMIN_MULTISIG unset"));
        gov.deployTimelock(address(0), DELAY);
    }

    /// The env entry point: MIN_DELAY defaults to 48 h and is floored at 24 h.
    /// The only test that sets these variables (tests share the process env).
    function test_deployTimelock_env_entry_point() public {
        vm.setEnv("ADMIN_MULTISIG", vm.toString(adminMs));
        vm.setEnv("MIN_DELAY", "3600");
        vm.expectRevert(bytes("MIN_DELAY < 86400"));
        gov.deployTimelock();

        vm.setEnv("MIN_DELAY", "172800");
        TimelockController tl = gov.deployTimelock();
        assertEq(tl.getMinDelay(), 172_800);
        assertTrue(tl.hasRole(tl.PROPOSER_ROLE(), adminMs));
    }

    // ------------------------------------------------------------------
    // the OZ pin
    // ------------------------------------------------------------------

    /// The TimelockController this project compiles (default profile: solc 0.8.20, optimizer
    /// 200, paris) is exactly OZ v5.0.2's; a different local checkout fails here.
    function test_timelock_runtime_code_is_pinned() public {
        assertEq(keccak256(type(TimelockController).runtimeCode), GovernancePins.TIMELOCK_RUNTIME_CODEHASH);
    }

    function test_deployTimelock_deploys_the_pinned_code() public {
        TimelockController tl = gov.deployTimelock(adminMs, DELAY);
        assertEq(address(tl).codehash, GovernancePins.TIMELOCK_RUNTIME_CODEHASH);
    }

    // ------------------------------------------------------------------
    // handover preconditions
    // ------------------------------------------------------------------

    function test_handover_refuses_a_timelock_without_code() public {
        vm.expectRevert(bytes("TIMELOCK has no code"));
        gov.handoverFrom(eoa, address(bridge), makeAddr("not-deployed"), adminMs, pauseMs);
    }

    function test_handover_refuses_a_short_timelock() public {
        address[] memory ms = new address[](1);
        ms[0] = adminMs;
        TimelockController short = new TimelockController(3600, ms, ms, address(0));
        vm.expectRevert(bytes("TIMELOCK delay < 86400"));
        gov.handoverFrom(eoa, address(bridge), address(short), adminMs, pauseMs);
    }

    function test_handover_refuses_a_bad_pause_multisig() public {
        TimelockController tl = gov.deployTimelock(adminMs, DELAY);
        vm.expectRevert(bytes("PAUSE_MULTISIG unset"));
        gov.handoverFrom(eoa, address(bridge), address(tl), adminMs, address(0));
        vm.expectRevert(bytes("PAUSE_MULTISIG == TIMELOCK"));
        gov.handoverFrom(eoa, address(bridge), address(tl), adminMs, address(tl));
    }

    function test_handover_refuses_a_timelock_that_is_not_the_pinned_oz_code() public {
        address fake = makeAddr("fake-timelock");
        vm.etch(fake, address(bridge).code);
        vm.expectRevert(bytes("TIMELOCK code hash != pinned OZ v5.0.2 TimelockController"));
        gov.handoverFrom(eoa, address(bridge), fake, adminMs, pauseMs);
    }

    function test_handover_refuses_open_execution() public {
        TimelockController tl = _timelock(_one(adminMs), _two(adminMs, address(0)), address(0));
        vm.expectRevert(bytes("TIMELOCK lets anyone execute"));
        gov.handoverFrom(eoa, address(bridge), address(tl), adminMs, pauseMs);
    }

    function test_handover_refuses_a_timelock_the_sender_administers() public {
        TimelockController tl = _timelock(_one(adminMs), _one(adminMs), eoa);
        vm.expectRevert(bytes("sender is TIMELOCK admin"));
        gov.handoverFrom(eoa, address(bridge), address(tl), adminMs, pauseMs);
    }

    function test_handover_refuses_a_timelock_the_sender_proposes_to() public {
        TimelockController tl = _timelock(_two(adminMs, eoa), _one(adminMs), address(0));
        vm.expectRevert(bytes("sender is TIMELOCK proposer"));
        gov.handoverFrom(eoa, address(bridge), address(tl), adminMs, pauseMs);
    }

    function test_handover_refuses_when_the_admin_multisig_cannot_propose() public {
        TimelockController tl = _timelock(_one(stranger), _one(adminMs), address(0));
        vm.expectRevert(bytes("ADMIN_MULTISIG is not TIMELOCK proposer"));
        gov.handoverFrom(eoa, address(bridge), address(tl), adminMs, pauseMs);
    }

    function test_handover_refuses_when_the_admin_multisig_cannot_execute() public {
        TimelockController tl = _timelock(_one(adminMs), _one(stranger), address(0));
        vm.expectRevert(bytes("ADMIN_MULTISIG is not TIMELOCK executor"));
        gov.handoverFrom(eoa, address(bridge), address(tl), adminMs, pauseMs);
    }

    function test_handover_refuses_an_admin_multisig_without_code() public {
        address keyOnly = makeAddr("admin-key");
        TimelockController tl = gov.deployTimelock(keyOnly, DELAY);
        vm.expectRevert(bytes("ADMIN_MULTISIG has no code"));
        gov.handoverFrom(eoa, address(bridge), address(tl), keyOnly, pauseMs);
        vm.expectRevert(bytes("ADMIN_MULTISIG unset"));
        gov.handoverFrom(eoa, address(bridge), address(tl), address(0), pauseMs);
    }

    function test_handover_refuses_the_sender_as_pauser() public {
        TimelockController tl = gov.deployTimelock(adminMs, DELAY);
        vm.expectRevert(bytes("PAUSE_MULTISIG == sender"));
        gov.handoverFrom(eoa, address(bridge), address(tl), adminMs, eoa);
    }

    function test_handover_refuses_the_admin_multisig_as_pauser() public {
        TimelockController tl = gov.deployTimelock(adminMs, DELAY);
        vm.expectRevert(bytes("PAUSE_MULTISIG == ADMIN_MULTISIG"));
        gov.handoverFrom(eoa, address(bridge), address(tl), adminMs, adminMs);
    }

    function test_handover_refuses_a_pauser_without_code() public {
        TimelockController tl = gov.deployTimelock(adminMs, DELAY);
        vm.expectRevert(bytes("PAUSE_MULTISIG has no code"));
        gov.handoverFrom(eoa, address(bridge), address(tl), adminMs, makeAddr("pause-key"));
    }

    function test_handover_refuses_a_broadcaster_that_is_not_admin() public {
        TimelockController tl = gov.deployTimelock(adminMs, DELAY);
        vm.expectRevert(bytes("broadcaster is not the bridge admin"));
        gov.handoverFrom(stranger, address(bridge), address(tl), adminMs, pauseMs);
    }

    // ------------------------------------------------------------------
    // acceptProposal: the Safe Transaction Builder batches
    // ------------------------------------------------------------------

    function test_acceptProposal_writes_the_two_safe_batches() public {
        TimelockController tl = _deployAndHandOver(bridge, eoa);
        (string memory schPath, string memory exePath) =
            gov.acceptProposal(address(bridge), address(tl), SALT, block.chainid, "cache/governance-test/local");
        assertEq(schPath, "cache/governance-test/local/31337-schedule-accept.json");
        assertEq(exePath, "cache/governance-test/local/31337-execute-accept.json");

        bytes memory accept = abi.encodeCall(IRandBridge.acceptAdmin, ());
        bytes memory wantSch = abi.encodeCall(
            TimelockController.schedule, (address(bridge), 0, accept, bytes32(0), SALT, DELAY)
        );
        bytes memory wantExe =
            abi.encodeCall(TimelockController.execute, (address(bridge), 0, accept, bytes32(0), SALT));

        bytes memory schData = _checkBatch(vm.readFile(schPath), address(tl));
        bytes memory exeData = _checkBatch(vm.readFile(exePath), address(tl));
        assertEq(schData, wantSch, "schedule calldata");
        assertEq(exeData, wantExe, "execute calldata");

        // And they do what they say, sent by the admin multisig.
        vm.prank(adminMs);
        (bool ok,) = address(tl).call(schData);
        assertTrue(ok, "schedule from the file");
        vm.warp(block.timestamp + DELAY);
        vm.prank(adminMs);
        (ok,) = address(tl).call(exeData);
        assertTrue(ok, "execute from the file");
        assertEq(bridge.admin(), address(tl));
    }

    function _checkBatch(string memory json, address to) internal view returns (bytes memory) {
        assertEq(vm.parseJsonString(json, ".version"), "1.0", "version");
        assertEq(vm.parseJsonString(json, ".chainId"), "31337", "chainId");
        assertTrue(bytes(vm.parseJsonString(json, ".meta.name")).length > 0, "meta.name");
        assertEq(vm.parseJsonAddress(json, ".transactions[0].to"), to, "to");
        assertEq(vm.parseJsonString(json, ".transactions[0].value"), "0", "value");
        assertFalse(vm.keyExistsJson(json, ".transactions[1]"), "exactly one transaction");
        return vm.parseJsonBytes(json, ".transactions[0].data");
    }

    function test_acceptProposal_refuses_a_wrong_chain_id() public {
        TimelockController tl = _deployAndHandOver(bridge, eoa);
        vm.expectRevert(bytes("CHAIN_ID != connected chain"));
        gov.acceptProposal(address(bridge), address(tl), SALT, 1, "cache/governance-test/local-wrong");
    }

    function test_acceptProposal_refuses_before_transferAdmin() public {
        TimelockController tl = gov.deployTimelock(adminMs, DELAY);
        vm.expectRevert(bytes("bridge.pendingAdmin() != TIMELOCK"));
        gov.acceptProposal(address(bridge), address(tl), SALT, block.chainid, "cache/governance-test/local-early");
    }

    // ------------------------------------------------------------------
    // fork: the live Ethereum and BSC bridges
    // ------------------------------------------------------------------

    address constant LIVE_BRIDGE = 0xd6EBD21C3dF90c9175EBdc8d6b377a9361604892;
    address constant LIVE_ADMIN = 0xe49Bd2571A549e8797bE649229F62891Fe300d0e;
    address constant ETH_USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant BSC_USDT = 0x55d398326f99059fF775485246999027B3197955;

    function test_fork_ethereum_handover() public {
        _forkHandover("ETH_FORK_URL", 1, ETH_USDT);
    }

    function test_fork_bsc_handover() public {
        _forkHandover("BSC_FORK_URL", 56, BSC_USDT);
    }

    function _forkHandover(string memory env, uint256 chainId, address usdt) internal {
        string memory url = vm.envOr(env, string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(url);
        assertEq(block.chainid, chainId, "forked the intended chain");
        gov = new Governance(); // contracts from before the fork do not exist on it
        _giveMultisigsCode();
        RandBridgeBase live = RandBridgeBase(LIVE_BRIDGE);
        assertEq(live.admin(), LIVE_ADMIN, "live admin is the EOA");
        assertEq(live.pendingAdmin(), address(0), "no live transfer outstanding");

        TimelockController tl = _deployAndHandOver(live, LIVE_ADMIN);
        assertEq(live.admin(), LIVE_ADMIN);
        assertEq(live.pendingAdmin(), address(tl));

        string memory dir = string.concat("cache/governance-test/fork-", vm.toString(chainId));
        (string memory schPath, string memory exePath) =
            gov.acceptProposal(LIVE_BRIDGE, address(tl), SALT, chainId, dir);
        bytes memory sch = vm.parseJsonBytes(vm.readFile(schPath), ".transactions[0].data");
        bytes memory exe = vm.parseJsonBytes(vm.readFile(exePath), ".transactions[0].data");
        vm.prank(adminMs);
        (bool ok,) = address(tl).call(sch);
        assertTrue(ok, "schedule");
        vm.warp(block.timestamp + DELAY);
        vm.prank(adminMs);
        (ok,) = address(tl).call(exe);
        assertTrue(ok, "execute");

        assertEq(live.admin(), address(tl), "admin is the timelock");
        assertEq(live.pauser(), pauseMs, "pauser is the pause multisig");
        assertEq(live.pendingAdmin(), address(0));

        vm.prank(LIVE_ADMIN);
        vm.expectRevert(IRandBridge.NotAdmin.selector);
        live.setToken(usdt, true, 0, 0);
        vm.prank(LIVE_ADMIN);
        vm.expectRevert(IRandBridge.NotAdmin.selector);
        live.unpause();
    }
}
