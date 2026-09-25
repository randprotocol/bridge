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
    /// not the pinned OZ code, has a delay under 24 h, lets anyone execute, gives the sender any
    /// role (admin, proposer, executor, canceller), or is not proposed to and executed by
    /// ADMIN_MULTISIG; and a pauser that is the sender, the timelock or ADMIN_MULTISIG. Both
    /// multisigs must pass `requireSafe` (canonical singleton, no module, threshold >= 2).
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
        requireSafe(adminMultisig, "ADMIN_MULTISIG");
        require(tl.hasRole(tl.PROPOSER_ROLE(), adminMultisig), "ADMIN_MULTISIG is not TIMELOCK proposer");
        require(tl.hasRole(tl.EXECUTOR_ROLE(), adminMultisig), "ADMIN_MULTISIG is not TIMELOCK executor");
        require(!tl.hasRole(tl.EXECUTOR_ROLE(), address(0)), "TIMELOCK lets anyone execute");
        require(!tl.hasRole(tl.DEFAULT_ADMIN_ROLE(), sender), "sender is TIMELOCK admin");
        require(!tl.hasRole(tl.PROPOSER_ROLE(), sender), "sender is TIMELOCK proposer");
        require(!tl.hasRole(tl.EXECUTOR_ROLE(), sender), "sender is TIMELOCK executor");
        require(!tl.hasRole(tl.CANCELLER_ROLE(), sender), "sender is TIMELOCK canceller");

        // The pauser: a second multisig, neither the old key nor the admin multisig.
        require(pauseMultisig != address(0), "PAUSE_MULTISIG unset");
        require(pauseMultisig != timelock, "PAUSE_MULTISIG == TIMELOCK");
        require(pauseMultisig != sender, "PAUSE_MULTISIG == sender");
        require(pauseMultisig != adminMultisig, "PAUSE_MULTISIG == ADMIN_MULTISIG");
        requireSafe(pauseMultisig, "PAUSE_MULTISIG");

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
    // The multisigs are Safes
    // ------------------------------------------------------------------

    /// A Safe with fewer signers than this is a key.
    uint256 public constant MIN_SAFE_THRESHOLD = 2;
    /// Safe's ModuleManager list sentinel: the first page of `getModulesPaginated` starts here.
    address internal constant SAFE_SENTINEL = address(0x1);

    /// The canonical Safe singletons (mastercopies) a Safe proxy may point at: v1.3.0
    /// `GnosisSafe` and `GnosisSafeL2`, v1.4.1 `Safe` and `SafeL2`, the "canonical" deployment of
    /// each in github.com/safe-global/safe-deployments (src/assets/v1.3.0/gnosis_safe.json,
    /// gnosis_safe_l2.json, v1.4.1/safe.json, safe_l2.json; all four listed for chains 1 and 56;
    /// read 2026-09-25 at main 7b1fb6d), plus the two v1.3.0 "eip155" deployments listed in the
    /// same files for chains 1 and 56, whose codeHash there (and `cast codehash` on Ethereum
    /// and BSC) equals the canonical ones'. `rand-bridge-audit --governance` pins the same six.
    function isCanonicalSafeSingleton(address singleton) public pure returns (bool) {
        return singleton == 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552 // v1.3.0
            || singleton == 0x69f4D1788e39c87893C980c06EdF4b7f686e2938 // v1.3.0 (eip155)
            || singleton == 0x3E5c63644E683549055b9Be8653de26E0B4CD36E // v1.3.0 L2
            || singleton == 0xfb1bffC9d739B8D520DaF37dF666da4C687191EA // v1.3.0 L2 (eip155)
            || singleton == 0x41675C099F32341bf84BFc5382aF534df5C7461a // v1.4.1
            || singleton == 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762; // v1.4.1 L2
    }

    /// keccak256 of the Safe proxy runtime code. Proxies have no immutables, so every Safe of a
    /// version has exactly this code. Read 2026-09-25 with `cast codehash` on Ethereum mainnet:
    /// v1.3.0 `GnosisSafeProxy` 0xd55fc3fcdb59c38237948bda9f14add783619f76,
    /// 0x11da15f4b1831a5119830902b14db9bf47a4fb59, 0xbf4673efcc7ad7680052d7d96a63d52338f5b2ed
    /// (equal to keccak256 of the v1.3.0 ProxyFactory 0xa6B71E26…6AB2 `proxyRuntimeCode()`, on
    /// Ethereum and BSC); v1.4.1 `SafeProxy` 0xc0468813ee19f271768f1b53b128ae5b1e0a70c3,
    /// 0x43703dd614c5ba3e87ec8211c56b64af14f3bd7b (a suffix of the v1.4.1 SafeProxyFactory
    /// 0x4e1DCf7A…ec67 `proxyCreationCode()`, on Ethereum and BSC). safe-deployments states only
    /// the factories' own code hashes, not the proxies'. `rand-bridge-audit` pins the same two.
    bytes32 internal constant SAFE_PROXY_130_CODEHASH =
        0xb89c1b3bdf2cf8827818646bce9a8f6e372885f8c55e5c07acbd307cb133b000;
    bytes32 internal constant SAFE_PROXY_141_CODEHASH =
        0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c;
    /// Safe FallbackManager: `keccak256("fallback_manager.handler.address")`.
    bytes32 internal constant FALLBACK_HANDLER_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    function isSafeProxyCodehash(bytes32 h) public pure returns (bool) {
        return h == SAFE_PROXY_130_CODEHASH || h == SAFE_PROXY_141_CODEHASH;
    }

    /// Reverts unless `safe` is a genuine Safe proxy (its code the v1.3.0/v1.4.1 proxy runtime,
    /// slot 0 a canonical singleton) whose fallback handler is not itself (GS400), with no
    /// enabled module (a module executes without any owner signature), a threshold of at least
    /// 2, and at least that many owners. Anything answering the views is not enough.
    function requireSafe(address safe, string memory what) public view {
        require(safe.code.length != 0, string.concat(what, " has no code"));
        require(
            isSafeProxyCodehash(safe.codehash),
            string.concat(what, " is not a Safe proxy (code is not the v1.3.0/v1.4.1 proxy runtime)")
        );
        address singleton = address(uint160(uint256(vm.load(safe, bytes32(0)))));
        require(
            isCanonicalSafeSingleton(singleton),
            string.concat(what, " is not a canonical Safe (slot 0 is not a v1.3.0/v1.4.1 singleton)")
        );
        require(
            address(uint160(uint256(vm.load(safe, FALLBACK_HANDLER_SLOT)))) != safe,
            string.concat(what, ": Safe fallback handler is the Safe itself (GS400)")
        );

        (bool ok, bytes memory ret) = safe.staticcall(abi.encodeWithSignature("getThreshold()"));
        require(ok && ret.length == 32, string.concat(what, ": getThreshold() unanswered"));
        uint256 threshold = abi.decode(ret, (uint256));
        require(threshold >= MIN_SAFE_THRESHOLD, string.concat(what, ": Safe threshold < 2"));

        (ok, ret) = safe.staticcall(abi.encodeWithSignature("getOwners()"));
        require(ok && ret.length >= 64, string.concat(what, ": getOwners() unanswered"));
        address[] memory owners = abi.decode(ret, (address[]));
        require(owners.length >= threshold, string.concat(what, ": Safe has fewer owners than its threshold"));

        (ok, ret) =
            safe.staticcall(abi.encodeWithSignature("getModulesPaginated(address,uint256)", SAFE_SENTINEL, 10));
        require(ok && ret.length >= 96, string.concat(what, ": getModulesPaginated() unanswered"));
        (address[] memory modules,) = abi.decode(ret, (address[], address));
        require(modules.length == 0, string.concat(what, ": Safe has modules: a module acts without signatures"));
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
