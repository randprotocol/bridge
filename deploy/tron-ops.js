#!/usr/bin/env node
// Post-deployment operations on the Tron endpoint. The signing key comes from the
// OPS_PRIVATE_KEY environment variable only — never from the command line.
//
//   OPS_PRIVATE_KEY=... node deploy/tron-ops.js fund <to> <sun>
//   OPS_PRIVATE_KEY=... node deploy/tron-ops.js set-token <bridge> <token> <perTransferCap> <dailyCap>
//   OPS_PRIVATE_KEY=... node deploy/tron-ops.js lock <bridge> <token> <amount> <recipientHash hex32> <relayerFee> <nonce>
//                       node deploy/tron-ops.js token-config <bridge> <token>
//
// BR-3 governance (docs/superpowers/specs/2026-09-25-br3-governance-design.md): the bridge admin
// moves behind an OpenZeppelin TimelockController (tron/contracts/governance, compiled by
// `tronbox compile`) driven by the admin multisig, the pauser to a separate multisig.
//
//   OPS_PRIVATE_KEY=... node deploy/tron-ops.js deploy-timelock <adminMultisig> [minDelay] [--yes]
//   OPS_PRIVATE_KEY=... node deploy/tron-ops.js set-pauser <pauseMultisig> [--bridge T...] [--yes]
//   OPS_PRIVATE_KEY=... node deploy/tron-ops.js transfer-admin <timelock> [--bridge T...] [--yes]
//                       node deploy/tron-ops.js timelock-schedule-accept <timelock> --from <adminMultisig>
//                       node deploy/tron-ops.js timelock-execute-accept <timelock> --from <adminMultisig>
//       (both also take [--bridge T...] [--salt 0x<32 bytes>] [--permission-id 2] [--expire-hours 23];
//        execute refuses unless the operation is pending, and prints whether it is ready and from when)
//
// The first three are signed by OPS_PRIVATE_KEY (the current bridge admin for set-pauser and
// transfer-admin): each prints the transaction it built and signs and broadcasts it only when
// `--yes` is given. The last two are sent by the admin multisig, a native Tron multi-signature
// account: they build the transaction UNSIGNED (owner = --from, the account's active permission
// --permission-id), print it and write it to deploy/governance/tron-<schedule|execute>-accept.json
// for that account's signers (tronWeb.trx.multiSign, then sendRawTransaction once the threshold is
// reached). They never sign. minDelay defaults to 172800 (48 h) and anything under 86400 is
// refused. --bridge defaults to the live Tron bridge TAqq2i8KfYpACPUc9f5e2gAjdSgXqmPpkU.
//
// Addresses are base58 (T...). TRON_RPC_URL overrides https://api.trongrid.io; TronWeb is the
// copy `deploy/trx.sh` installs into tron/node_modules.
const fs = require('fs');
const path = require('path');
const { TronWeb } = require(path.join(__dirname, '..', 'tron', 'node_modules', 'tronweb'));

const FEE_LIMIT = 100_000_000; // 100 TRX
const DEPLOY_FEE_LIMIT = 1_000_000_000; // 1000 TRX, as tron/tronbox.js
const TRON_BRIDGE = 'TAqq2i8KfYpACPUc9f5e2gAjdSgXqmPpkU';
const DEFAULT_MIN_DELAY = 172_800; // 48 h
const MIN_ALLOWED_DELAY = 86_400; // 24 h
const TRON_ZERO_HEX = '410000000000000000000000000000000000000000';
const ZERO32 = '0x' + '00'.repeat(32);
const ACCEPT_ADMIN = '0x0e18b681'; // bytes4(keccak256("acceptAdmin()"))
const ARTIFACT = path.join(__dirname, '..', 'tron', 'build', 'contracts', 'TimelockController.json');
const OUT_DIR = path.join(__dirname, 'governance');

async function settle(tronWeb, id) {
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 3000));
    const info = await tronWeb.trx.getTransactionInfo(id);
    if (info && info.id) {
      const result = (info.receipt && info.receipt.result) || 'SUCCESS';
      console.log(`${id} block ${info.blockNumber} ${result} fee ${(info.fee || 0) / 1e6} TRX`);
      if (result !== 'SUCCESS') process.exit(1);
      return;
    }
  }
  console.error(`${id}: no receipt after 120 s`);
  process.exit(1);
}

async function call(tronWeb, contract, selector, parameters) {
  const tx = await tronWeb.transactionBuilder.triggerSmartContract(
    contract, selector, { feeLimit: FEE_LIMIT }, parameters);
  if (!tx.result || !tx.result.result) throw new Error(`build failed: ${JSON.stringify(tx)}`);
  const signed = await tronWeb.trx.sign(tx.transaction);
  const sent = await tronWeb.trx.sendRawTransaction(signed);
  if (!sent.result) throw new Error(`broadcast refused: ${JSON.stringify(sent)}`);
  await settle(tronWeb, sent.txid);
}

// ---------------------------------------------------------------------------------------------
// BR-3 governance
// ---------------------------------------------------------------------------------------------

/// Splits `--flag value` / `--yes` out of argv.
function parseFlags(argv) {
  const args = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--yes') flags.yes = true;
    else if (argv[i].startsWith('--')) flags[argv[i].slice(2)] = argv[++i];
    else args.push(argv[i]);
  }
  return { args, flags };
}

function requireAddress(tronWeb, what, a) {
  if (!a || !tronWeb.isAddress(a)) throw new Error(`${what}: not a Tron address: ${a}`);
  if (tronWeb.address.toHex(a) === TRON_ZERO_HEX) throw new Error(`${what} is the zero address`);
  return a;
}

/// Constructor arguments of TimelockController(minDelay, proposers, executors, admin):
/// the admin multisig proposes and executes (and, as a proposer, cancels); no timelock admin.
function timelockConstructorParams(adminMultisig, minDelay) {
  const delay = minDelay === undefined ? DEFAULT_MIN_DELAY : Number(minDelay);
  if (!Number.isSafeInteger(delay) || delay < MIN_ALLOWED_DELAY) throw new Error('MIN_DELAY < 86400');
  if (!adminMultisig) throw new Error('adminMultisig unset');
  return [delay, [adminMultisig], [adminMultisig], TRON_ZERO_HEX];
}

/// The CreateSmartContract transaction for the tronbox-compiled TimelockController, unsigned.
async function buildTimelockDeployTx(tronWeb, artifact, parameters, owner, blockHeader) {
  const options = {
    abi: artifact.abi,
    bytecode: artifact.bytecode.replace(/^0x/, ''),
    parameters,
    feeLimit: DEPLOY_FEE_LIMIT,
    name: 'TimelockController',
  };
  if (blockHeader) options.blockHeader = blockHeader;
  return tronWeb.transactionBuilder.createSmartContract(options, owner);
}

/// schedule/execute(bridge, 0, acceptAdmin(), 0, salt[, delay]) on the timelock, from `from`
/// under its permission `permissionId`, built locally and unsigned.
async function buildTimelockAcceptTx(tronWeb, which, o) {
  const params = [
    { type: 'address', value: o.bridge },
    { type: 'uint256', value: 0 },
    { type: 'bytes', value: ACCEPT_ADMIN },
    { type: 'bytes32', value: ZERO32 },
    { type: 'bytes32', value: o.salt },
  ];
  let sig;
  if (which === 'schedule') {
    params.push({ type: 'uint256', value: o.delay });
    sig = 'schedule(address,uint256,bytes,bytes32,bytes32,uint256)';
  } else if (which === 'execute') {
    sig = 'execute(address,uint256,bytes,bytes32,bytes32)';
  } else {
    throw new Error(`unknown timelock call ${which}`);
  }
  const options = { feeLimit: FEE_LIMIT, txLocal: true, permissionId: o.permissionId };
  if (o.blockHeader) options.blockHeader = o.blockHeader;
  const built = await tronWeb.transactionBuilder.triggerSmartContract(o.timelock, sig, options, params, o.from);
  return built.transaction;
}

/// A constant call, returning the 32-byte words of the result.
async function view(tronWeb, contract, selector, parameters = []) {
  const out = await tronWeb.transactionBuilder.triggerConstantContract(contract, selector, {}, parameters);
  const hex = out && out.constant_result && out.constant_result[0];
  if (!hex || (out.result && out.result.message)) throw new Error(`${contract}.${selector} failed (no code?)`);
  return hex.match(/.{64}/g) || [];
}
const wordAddress = (tronWeb, w) => tronWeb.address.fromHex('41' + w.slice(24));
const wordUint = (w) => BigInt('0x' + w);

async function minDelayOf(tronWeb, timelock) {
  const [w] = await view(tronWeb, timelock, 'getMinDelay()');
  return wordUint(w);
}

async function bridgeRoles(tronWeb, bridge) {
  const [admin] = await view(tronWeb, bridge, 'admin()');
  const [pending] = await view(tronWeb, bridge, 'pendingAdmin()');
  const [pauser] = await view(tronWeb, bridge, 'pauser()');
  return { admin: wordAddress(tronWeb, admin), pendingAdmin: wordAddress(tronWeb, pending), pauser: wordAddress(tronWeb, pauser) };
}

/// The acceptAdmin operation's id (the timelock's own hashOperation), which must be pending
/// (scheduled, not yet executed or cancelled); whether it is ready, and when it becomes so.
async function checkExecutable(tronWeb, o) {
  const [idWord] = await view(tronWeb, o.timelock, 'hashOperation(address,uint256,bytes,bytes32,bytes32)', [
    { type: 'address', value: o.bridge },
    { type: 'uint256', value: 0 },
    { type: 'bytes', value: ACCEPT_ADMIN },
    { type: 'bytes32', value: ZERO32 },
    { type: 'bytes32', value: o.salt },
  ]);
  const id = '0x' + idWord;
  const arg = [{ type: 'bytes32', value: id }];
  const [pending] = await view(tronWeb, o.timelock, 'isOperationPending(bytes32)', arg);
  if (wordUint(pending) !== 1n) {
    throw new Error(`operation ${id} is not pending on ${o.timelock} (never scheduled with this salt, cancelled, or done)`);
  }
  const [ready] = await view(tronWeb, o.timelock, 'isOperationReady(bytes32)', arg);
  const [ts] = await view(tronWeb, o.timelock, 'getTimestamp(bytes32)', arg);
  return { id, ready: wordUint(ready) === 1n, timestamp: wordUint(ts) };
}

function same(tronWeb, a, b) {
  return tronWeb.address.toHex(a) === tronWeb.address.toHex(b);
}

/// Prints `tx`; signs and broadcasts it only with --yes.
async function confirmAndSend(tronWeb, tx, summary, yes) {
  console.log(summary);
  console.log(JSON.stringify(tx, null, 2));
  if (!yes) {
    console.log('NOT SIGNED: re-run with --yes to sign this transaction and broadcast it.');
    return;
  }
  const signed = await tronWeb.trx.sign(tx);
  const sent = await tronWeb.trx.sendRawTransaction(signed);
  if (!sent.result) throw new Error(`broadcast refused: ${JSON.stringify(sent)}`);
  await settle(tronWeb, sent.txid || tx.txID);
}

async function governance(tronWeb, command, argv, key) {
  const { args, flags } = parseFlags(argv);
  const bridge = requireAddress(tronWeb, '--bridge', flags.bridge || TRON_BRIDGE);
  const signerOnly = () => {
    if (!key) throw new Error('OPS_PRIVATE_KEY is not set');
    console.log(`signer ${tronWeb.defaultAddress.base58}`);
    return tronWeb.defaultAddress.base58;
  };

  if (command === 'deploy-timelock') {
    const adminMultisig = requireAddress(tronWeb, 'adminMultisig', args[0]);
    const parameters = timelockConstructorParams(adminMultisig, args[1]);
    const signer = signerOnly();
    const artifactPath = flags.artifact || ARTIFACT;
    if (!fs.existsSync(artifactPath)) throw new Error(`${artifactPath} missing: run \`npm run compile\` in tron/`);
    const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
    const tx = await buildTimelockDeployTx(tronWeb, artifact, parameters, signer);
    await confirmAndSend(tronWeb, tx, [
      `deploy TimelockController from ${signer}`,
      `  minDelay ${parameters[0]} s, proposer = executor = canceller ${adminMultisig}, admin none`,
      `  address ${tronWeb.address.fromHex(tx.contract_address)}`,
    ].join('\n'), flags.yes);
  } else if (command === 'set-pauser') {
    const pauseMultisig = requireAddress(tronWeb, 'pauseMultisig', args[0]);
    const signer = signerOnly();
    const roles = await bridgeRoles(tronWeb, bridge);
    if (!same(tronWeb, roles.admin, signer)) throw new Error(`signer is not the bridge admin (${roles.admin})`);
    if (same(tronWeb, pauseMultisig, roles.admin) || same(tronWeb, pauseMultisig, roles.pendingAdmin)) {
      throw new Error('pauseMultisig must differ from the admin and the pending admin');
    }
    const { transaction } = await tronWeb.transactionBuilder.triggerSmartContract(
      bridge, 'setPauser(address)', { feeLimit: FEE_LIMIT }, [{ type: 'address', value: pauseMultisig }], signer);
    await confirmAndSend(tronWeb, transaction,
      `bridge ${bridge}: setPauser(${pauseMultisig}) (pauser now ${roles.pauser})`, flags.yes);
  } else if (command === 'transfer-admin') {
    const timelock = requireAddress(tronWeb, 'timelock', args[0]);
    const signer = signerOnly();
    const delay = await minDelayOf(tronWeb, timelock);
    if (delay < BigInt(MIN_ALLOWED_DELAY)) throw new Error(`timelock getMinDelay() = ${delay} < 86400`);
    const roles = await bridgeRoles(tronWeb, bridge);
    if (!same(tronWeb, roles.admin, signer)) throw new Error(`signer is not the bridge admin (${roles.admin})`);
    if (same(tronWeb, roles.pauser, timelock)) throw new Error('the pauser is the timelock: run set-pauser first');
    const { transaction } = await tronWeb.transactionBuilder.triggerSmartContract(
      bridge, 'transferAdmin(address)', { feeLimit: FEE_LIMIT }, [{ type: 'address', value: timelock }], signer);
    await confirmAndSend(tronWeb, transaction,
      `bridge ${bridge}: transferAdmin(${timelock}) (timelock minDelay ${delay} s; ${signer} stays admin until it accepts)`,
      flags.yes);
  } else {
    // timelock-schedule-accept | timelock-execute-accept: unsigned, for the multisig's signers.
    const which = command === 'timelock-schedule-accept' ? 'schedule' : 'execute';
    const timelock = requireAddress(tronWeb, 'timelock', args[0]);
    const from = requireAddress(tronWeb, '--from (the admin multisig account)', flags.from);
    const salt = flags.salt || ZERO32;
    if (!/^0x[0-9a-fA-F]{64}$/.test(salt)) throw new Error('--salt must be 0x + 32 bytes of hex');
    const permissionId = Number(flags['permission-id'] || 2);
    const expireHours = Number(flags['expire-hours'] || 23);
    if (!(expireHours > 0 && expireHours < 24)) throw new Error('--expire-hours must be in (0, 24)');

    const delay = await minDelayOf(tronWeb, timelock);
    if (delay < BigInt(MIN_ALLOWED_DELAY)) throw new Error(`timelock getMinDelay() = ${delay} < 86400`);
    const roles = await bridgeRoles(tronWeb, bridge);
    if (!same(tronWeb, roles.pendingAdmin, timelock)) {
      throw new Error(`bridge.pendingAdmin() is ${roles.pendingAdmin}, not the timelock: run transfer-admin first`);
    }
    const role = which === 'schedule' ? 'PROPOSER_ROLE()' : 'EXECUTOR_ROLE()';
    const [roleWord] = await view(tronWeb, timelock, role);
    const [has] = await view(tronWeb, timelock, 'hasRole(bytes32,address)',
      [{ type: 'bytes32', value: '0x' + roleWord }, { type: 'address', value: from }]);
    if (wordUint(has) !== 1n) throw new Error(`${from} does not hold ${role} on the timelock`);

    if (which === 'execute') {
      const op = await checkExecutable(tronWeb, { timelock, bridge, salt });
      const when = new Date(Number(op.timestamp) * 1000).toISOString();
      console.log(`operation ${op.id}: pending, ${op.ready ? 'READY to execute' : 'NOT ready yet'} ` +
        `(executable from ${when}, timestamp ${op.timestamp})`);
    }
    let tx = await buildTimelockAcceptTx(tronWeb, which, { timelock, bridge, salt, delay: delay.toString(), from, permissionId });
    tx = await tronWeb.transactionBuilder.extendExpiration(tx, Math.floor(expireHours * 3600) - 60, { txLocal: true });
    const summary = which === 'schedule'
      ? `timelock ${timelock}: schedule(${bridge}, 0, acceptAdmin(), 0, ${salt}, ${delay}) — execute after ${delay} s`
      : `timelock ${timelock}: execute(${bridge}, 0, acceptAdmin(), 0, ${salt}) — only once the schedule's delay has passed`;
    fs.mkdirSync(OUT_DIR, { recursive: true });
    const out = path.join(OUT_DIR, `tron-${which}-accept.json`);
    fs.writeFileSync(out, JSON.stringify({
      description: `BR-3: ${summary}`,
      signers: `UNSIGNED. Owner ${from}, permission id ${permissionId}. Each signer: ` +
        `tx = await tronWeb.trx.multiSign(tx, <own key>, ${permissionId}); once the threshold is met, ` +
        'tronWeb.trx.sendRawTransaction(tx). Expires ' + new Date(tx.raw_data.expiration).toISOString() +
        '; rebuild with this command after that.',
      transaction: tx,
    }, null, 2) + '\n');
    console.log(summary);
    console.log(JSON.stringify(tx, null, 2));
    console.log(`UNSIGNED, written to ${out} for the signers of ${from}`);
  }
}

const GOVERNANCE_COMMANDS = ['deploy-timelock', 'set-pauser', 'transfer-admin', 'timelock-schedule-accept', 'timelock-execute-accept'];

async function main() {
  const [command, ...args] = process.argv.slice(2);
  const key = (process.env.OPS_PRIVATE_KEY || '').replace(/^0x/, '');
  const tronWeb = new TronWeb({
    fullHost: process.env.TRON_RPC_URL || 'https://api.trongrid.io',
    privateKey: key || '01'.padStart(64, '0'),
  });
  if (command === 'token-config') {
    const [bridge, token] = args;
    tronWeb.setAddress(bridge);
    const out = await tronWeb.transactionBuilder.triggerConstantContract(
      bridge, 'tokenConfig(address)', {}, [{ type: 'address', value: token }]);
    console.log(out.constant_result[0].match(/.{64}/g).map((w) => BigInt('0x' + w).toString()).join(' '));
    return;
  }
  if (GOVERNANCE_COMMANDS.includes(command)) {
    await governance(tronWeb, command, args, key);
    return;
  }
  if (!key) throw new Error('OPS_PRIVATE_KEY is not set');
  console.log(`signer ${tronWeb.defaultAddress.base58}`);
  if (command === 'fund') {
    const [to, sun] = args;
    const sent = await tronWeb.trx.sendTransaction(to, Number(sun));
    if (!sent.result) throw new Error(`broadcast refused: ${JSON.stringify(sent)}`);
    await settle(tronWeb, sent.txid || sent.transaction.txID);
  } else if (command === 'set-token') {
    const [bridge, token, perTransferCap, dailyCap] = args;
    await call(tronWeb, bridge, 'setToken(address,bool,uint256,uint256)', [
      { type: 'address', value: token }, { type: 'bool', value: true },
      { type: 'uint256', value: perTransferCap }, { type: 'uint256', value: dailyCap }]);
  } else if (command === 'lock') {
    const [bridge, token, amount, recipient, relayerFee, nonce] = args;
    await call(tronWeb, token, 'approve(address,uint256)', [
      { type: 'address', value: bridge }, { type: 'uint256', value: amount }]);
    await call(tronWeb, bridge, 'lock(address,uint256,bytes32,uint256,uint32)', [
      { type: 'address', value: token }, { type: 'uint256', value: amount },
      { type: 'bytes32', value: '0x' + recipient.replace(/^0x/, '') },
      { type: 'uint256', value: relayerFee }, { type: 'uint32', value: nonce }]);
  } else {
    throw new Error(`usage: fund | set-token | lock | token-config | ${GOVERNANCE_COMMANDS.join(' | ')}`);
  }
}

if (require.main === module) {
  main().catch((e) => { console.error(e.message || e); process.exit(1); });
}

module.exports = { timelockConstructorParams, buildTimelockDeployTx, buildTimelockAcceptTx, checkExecutable, parseFlags, TRON_ZERO_HEX, ACCEPT_ADMIN };
