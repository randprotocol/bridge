// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IRandBridge} from "../src/interfaces/IRandBridge.sol";
import {GovernancePins} from "./GovernancePins.sol";

interface IBridgeRoles {
    function admin() external view returns (address);
    function pendingAdmin() external view returns (address);
    function pauser() external view returns (address);
}

/// @notice BR-3 governance handover for an EVM endpoint (Ethereum, BSC): the
/// admin role moves behind an OpenZeppelin `TimelockController` driven by the
/// admin multisig, and the pauser to a separate pause multisig. Design:
/// `docs/superpowers/specs/2026-09-25-br3-governance-design.md`.
///
/// No key is read from the environment. Broadcasting steps are signed by
/// whatever wallet forge is given (`--account`, `--ledger`, ...), and only when
/// the operator passes `--broadcast`; without it every step is a dry run.
///
/// ```
/// # 1. deploy the timelock (any funded key)
/// ADMIN_MULTISIG=0x... [MIN_DELAY=172800] forge script script/Governance.s.sol:Governance \
///     --sig "deployTimelock()" --rpc-url $RPC --account deployer [--broadcast]
///
/// # 2+3. setPauser + transferAdmin, from the CURRENT bridge admin. `--sender` MUST be that
/// #      admin: the checks (and the broadcast) are made for msg.sender, which is --sender.
/// BRIDGE=0x... TIMELOCK=0x... ADMIN_MULTISIG=0x... PAUSE_MULTISIG=0x... \
///     forge script script/Governance.s.sol:Governance --sig "handover()" --rpc-url $RPC \
///     --sender <current admin> --account bridge-admin [--broadcast]
///
/// # 4+5. the Safe batches for the admin multisig (no transaction is sent)
/// BRIDGE=0x... TIMELOCK=0x... CHAIN_ID=1 [SALT=0x...] forge script script/Governance.s.sol:Governance \
///     --sig "acceptProposal()" --rpc-url $RPC
/// ```
///
/// Step 4 is `deploy/governance/<chainid>-schedule-accept.json`, imported into
/// the Safe Transaction Builder and signed by the admin multisig; step 5,
/// `<chainid>-execute-accept.json`, is sent the same way once `MIN_DELAY` has
/// passed. Until step 5 the EOA stays admin and can cancel with
/// `transferAdmin(address(0))`.
contract Governance is Script {
    /// 48 h: the delay the design asks for.
    uint256 public constant DEFAULT_MIN_DELAY = 172_800;
    /// 24 h: nothing shorter is accepted, here or as a handover target.
    uint256 public constant MIN_ALLOWED_DELAY = 86_400;

    string internal constant OUT_DIR = "../deploy/governance";

    // ------------------------------------------------------------------
    // 1. deployTimelock
    // ------------------------------------------------------------------

    function deployTimelock() external returns (TimelockController) {
        return deployTimelock(vm.envAddress("ADMIN_MULTISIG"), vm.envOr("MIN_DELAY", DEFAULT_MIN_DELAY));
    }

    /// proposers = executors = [adminMultisig] (OZ also makes every proposer a
    /// canceller), and no timelock admin: the delay and the roles can then
    /// only change through an operation that itself waits out the delay.
    function deployTimelock(address adminMultisig, uint256 minDelay) public returns (TimelockController tl) {
        require(adminMultisig != address(0), "ADMIN_MULTISIG unset");
        require(minDelay >= MIN_ALLOWED_DELAY, "MIN_DELAY < 86400");

        bytes32 codeHash = keccak256(type(TimelockController).runtimeCode);
        require(
            codeHash == GovernancePins.TIMELOCK_RUNTIME_CODEHASH,
            "compiled TimelockController != pinned OZ v5.0.2 (wrong lib checkout or profile?)"
        );

        address[] memory holders = new address[](1);
        holders[0] = adminMultisig;

        vm.startBroadcast();
        tl = new TimelockController(minDelay, holders, holders, address(0));
        vm.stopBroadcast();
        require(address(tl).codehash == codeHash, "deployed code != pinned code");

        console2.log("TimelockController", address(tl));
        console2.log("  runtime code hash");
        console2.logBytes32(codeHash);
        console2.log("  minDelay (s)     ", minDelay);
        console2.log("  proposer/executor/canceller", adminMultisig);
    }

    // ------------------------------------------------------------------
    // 2 + 3. handover
    // ------------------------------------------------------------------

    /// Broadcast by the current bridge admin, which must be passed as `--sender <current admin>`:
    /// forge runs the entry point with `msg.sender` = `--sender`. It refuses a timelock that is
    /// not the pinned OZ code, has a delay under 24 h, lets anyone execute, is administered or
    /// proposed to by the sender, or is not proposed to and executed by ADMIN_MULTISIG (a
    /// contract); and a pauser that is not a contract or is the sender, the timelock or
    /// ADMIN_MULTISIG.
    function handover() external {
        handoverFrom(
            msg.sender,
            vm.envAddress("BRIDGE"),
            vm.envAddress("TIMELOCK"),
            vm.envAddress("ADMIN_MULTISIG"),
            vm.envAddress("PAUSE_MULTISIG")
        );
    }

    /// Every check that the handover leaves no single key in control, then the two calls.
    function handoverFrom(address sender, address bridge, address timelock, address adminMultisig, address pauseMultisig)
        public
    {
        // The timelock: the pinned OZ code, a real delay, driven by the admin multisig only.
        require(timelock.code.length != 0, "TIMELOCK has no code");
        require(
            timelock.codehash == GovernancePins.TIMELOCK_RUNTIME_CODEHASH,
            "TIMELOCK code hash != pinned OZ v5.0.2 TimelockController"
        );
        TimelockController tl = TimelockController(payable(timelock));
        require(tl.getMinDelay() >= MIN_ALLOWED_DELAY, "TIMELOCK delay < 86400");
        require(adminMultisig != address(0), "ADMIN_MULTISIG unset");
        require(adminMultisig.code.length != 0, "ADMIN_MULTISIG has no code");
        require(tl.hasRole(tl.PROPOSER_ROLE(), adminMultisig), "ADMIN_MULTISIG is not TIMELOCK proposer");
        require(tl.hasRole(tl.EXECUTOR_ROLE(), adminMultisig), "ADMIN_MULTISIG is not TIMELOCK executor");
        require(!tl.hasRole(tl.EXECUTOR_ROLE(), address(0)), "TIMELOCK lets anyone execute");
        require(!tl.hasRole(tl.DEFAULT_ADMIN_ROLE(), sender), "sender is TIMELOCK admin");
        require(!tl.hasRole(tl.PROPOSER_ROLE(), sender), "sender is TIMELOCK proposer");

        // The pauser: a second multisig, neither the old key nor the admin multisig.
        require(pauseMultisig != address(0), "PAUSE_MULTISIG unset");
        require(pauseMultisig != timelock, "PAUSE_MULTISIG == TIMELOCK");
        require(pauseMultisig != sender, "PAUSE_MULTISIG == sender");
        require(pauseMultisig != adminMultisig, "PAUSE_MULTISIG == ADMIN_MULTISIG");
        require(pauseMultisig.code.length != 0, "PAUSE_MULTISIG has no code");

        require(IBridgeRoles(bridge).admin() == sender, "broadcaster is not the bridge admin");

        vm.startBroadcast(sender);
        IRandBridge(bridge).setPauser(pauseMultisig);
        IRandBridge(bridge).transferAdmin(timelock);
        vm.stopBroadcast();

        console2.log("bridge      ", bridge);
        console2.log("pauser   -> ", pauseMultisig);
        console2.log("pending  -> ", IBridgeRoles(bridge).pendingAdmin());
        console2.log("admin (until the timelock accepts)", IBridgeRoles(bridge).admin());
    }

    // ------------------------------------------------------------------
    // 4 + 5. acceptProposal: Safe Transaction Builder batches
    // ------------------------------------------------------------------

    function acceptProposal() external returns (string memory, string memory) {
        return acceptProposal(
            vm.envAddress("BRIDGE"),
            vm.envAddress("TIMELOCK"),
            vm.envOr("SALT", bytes32(0)),
            vm.envOr("CHAIN_ID", block.chainid),
            OUT_DIR
        );
    }

    /// The calldata the admin multisig sends to the timelock: `schedule` now,
    /// `execute` after `getMinDelay()`.
    function acceptCalls(address bridge, address timelock, bytes32 salt)
        public
        view
        returns (bytes memory scheduleCall, bytes memory executeCall)
    {
        bytes memory accept = abi.encodeCall(IRandBridge.acceptAdmin, ());
        uint256 delay = TimelockController(payable(timelock)).getMinDelay();
        scheduleCall = abi.encodeCall(TimelockController.schedule, (bridge, 0, accept, bytes32(0), salt, delay));
        executeCall = abi.encodeCall(TimelockController.execute, (bridge, 0, accept, bytes32(0), salt));
    }

    function acceptProposal(address bridge, address timelock, bytes32 salt, uint256 chainId, string memory outDir)
        public
        returns (string memory schedulePath, string memory executePath)
    {
        require(chainId == block.chainid, "CHAIN_ID != connected chain");
        require(timelock.code.length != 0, "TIMELOCK has no code");
        require(IBridgeRoles(bridge).pendingAdmin() == timelock, "bridge.pendingAdmin() != TIMELOCK");

        (bytes memory sch, bytes memory exe) = acceptCalls(bridge, timelock, salt);
        string memory chain = vm.toString(chainId);
        vm.createDir(outDir, true);
        schedulePath = string.concat(outDir, "/", chain, "-schedule-accept.json");
        executePath = string.concat(outDir, "/", chain, "-execute-accept.json");

        string memory what = string.concat(
            "bridge ", vm.toString(bridge), ".acceptAdmin() via timelock ", vm.toString(timelock),
            ", salt ", vm.toString(salt)
        );
        vm.writeJson(
            _safeBatch("sch", chain, timelock, sch, "BR-3 step 4: schedule acceptAdmin", string.concat("Schedule ", what)),
            schedulePath
        );
        vm.writeJson(
            _safeBatch(
                "exe",
                chain,
                timelock,
                exe,
                "BR-3 step 5: execute acceptAdmin",
                string.concat("Execute (after minDelay) ", what)
            ),
            executePath
        );

        console2.log("wrote", schedulePath);
        console2.log("wrote", executePath);
    }

    /// One-transaction batch in the Safe Transaction Builder's import format.
    function _safeBatch(
        string memory key,
        string memory chainId,
        address to,
        bytes memory data,
        string memory name,
        string memory description
    ) internal returns (string memory) {
        string memory txKey = string.concat(key, ".tx");
        vm.serializeAddress(txKey, "to", to);
        vm.serializeString(txKey, "value", "0");
        string memory txJson = vm.serializeBytes(txKey, "data", data);

        string memory metaKey = string.concat(key, ".meta");
        vm.serializeString(metaKey, "name", name);
        vm.serializeString(metaKey, "description", description);
        vm.serializeString(metaKey, "txBuilderVersion", "1.16.5");
        vm.serializeString(metaKey, "createdFromSafeAddress", "");
        string memory meta = vm.serializeString(metaKey, "createdFromOwnerAddress", "");

        vm.serializeJson(key, string.concat('{"transactions":[', txJson, "]}"));
        vm.serializeString(key, "version", "1.0");
        vm.serializeString(key, "chainId", chainId);
        vm.serializeUint(key, "createdAt", vm.unixTime());
        return vm.serializeString(key, "meta", meta);
    }
}
