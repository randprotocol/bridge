// Offline tests of deploy/tron-ops.js's BR-3 governance commands: `node --test deploy/`.
// TronWeb is the real library (address and ABI utilities), with every network method replaced
// by a stub that serves a fake bridge and a fake TimelockController. Nothing is signed or sent.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { TronWeb } = require(path.join(__dirname, '..', 'tron', 'node_modules', 'tronweb'));
const ops = require('./tron-ops.js');

const FIXTURE = path.join(__dirname, '..', 'daemons', 'tests', 'fixtures',
  'oz-v5.0.2-TimelockController.tronbox.runtime.hex');
const TIMELOCK_CODE = fs.readFileSync(FIXTURE, 'utf8').trim().replace(/^0x/, '');

const b58 = (hex20) => TronWeb.address.fromHex('41' + hex20);
const BRIDGE = 'TAqq2i8KfYpACPUc9f5e2gAjdSgXqmPpkU';
const TIMELOCK = b58('11'.repeat(20)); // any address: served by the stub
const ADMIN_MS = b58('33'.repeat(20));
const PAUSE_MS = b58('22'.repeat(20));
const SIGNER = 'TWoyjUS76DCsgDxyhTQMRCVsaA2ptKh9mh'; // the current admin (a key)
const ZERO = 'T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb';

const role = (name) => (name === 'DEFAULT_ADMIN_ROLE' ? '0x' + '00'.repeat(32) : TronWeb.sha3(name));

/// A TronWeb whose network is `state`: the bridge's roles, the timelock's code, delay, roles
/// and operations. Records every transaction it is asked to build.
function stubbed(state) {
  const tw = new TronWeb({ fullHost: 'http://127.0.0.1:1', privateKey: '01'.padStart(64, '0') });
  const hex = (a) => tw.address.toHex(a).toLowerCase();
  const word = (v) => BigInt(v).toString(16).padStart(64, '0');
  const addrWord = (a) => hex(a).slice(2).padStart(64, '0');
  const has = (r, a) => (state.roles[r] || []).some((x) => hex(x) === hex(a));
  tw.defaultAddress = { base58: state.signer, hex: hex(state.signer) };
  tw.built = [];
  tw.trx.getContractInfo = async (a) => (hex(a) === hex(TIMELOCK)
    ? { runtimecode: state.code, smart_contract: {} } : {});
  tw.transactionBuilder.triggerConstantContract = async (contract, fn, _o, params = []) => {
    let out;
    if (hex(contract) === hex(BRIDGE)) {
      out = { 'admin()': addrWord(state.admin), 'pendingAdmin()': addrWord(state.pendingAdmin),
        'pauser()': addrWord(state.pauser) }[fn];
    } else if (hex(contract) === hex(TIMELOCK) && state.code) {
      if (fn === 'getMinDelay()') out = word(state.delay);
      else if (fn === 'hasRole(bytes32,address)') out = word(has(params[0].value, params[1].value) ? 1 : 0);
      else if (fn === 'hashOperation(address,uint256,bytes,bytes32,bytes32)') {
        out = tw.utils.ethersUtils.keccak256(tw.utils.ethersUtils.toUtf8Bytes(JSON.stringify(params))).slice(2);
      } else if (fn === 'isOperationPending(bytes32)') out = word(state.pending ? 1 : 0);
      else if (fn === 'isOperationReady(bytes32)') out = word(state.ready ? 1 : 0);
      else if (fn === 'getTimestamp(bytes32)') out = word(1_790_000_000);
    }
    if (out === undefined) return { result: { message: 'REVERT' } };
    return { result: { result: true }, constant_result: [out] };
  };
  tw.transactionBuilder.triggerSmartContract = async (contract, fn, options, params, from) => {
    tw.built.push({ contract, fn, options, params, from });
    return { result: { result: true },
      transaction: { txID: 'ab'.repeat(32), raw_data: { expiration: 1_790_000_000_000, contract: [] } } };
  };
  tw.transactionBuilder.extendExpiration = async (tx) => tx;
  return tw;
}

function compliant() {
  return {
    signer: SIGNER,
    admin: SIGNER,
    pendingAdmin: ZERO,
    pauser: PAUSE_MS,
    code: TIMELOCK_CODE,
    delay: 172_800,
    roles: {
      [role('DEFAULT_ADMIN_ROLE')]: [TIMELOCK],
      [role('PROPOSER_ROLE')]: [ADMIN_MS],
      [role('CANCELLER_ROLE')]: [ADMIN_MS],
      [role('EXECUTOR_ROLE')]: [ADMIN_MS],
    },
    pending: true,
    ready: false,
  };
}

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'tron-ops-test-'));
const KEY = '01'.padStart(64, '0');

test('the pinned Tron timelock hash is the tronbox build (fixture, and tron/build when compiled)', () => {
  const tw = new TronWeb({ fullHost: 'http://127.0.0.1:1' });
  assert.equal(tw.utils.ethersUtils.keccak256('0x' + TIMELOCK_CODE), ops.TRON_TIMELOCK_RUNTIME_KECCAK);
  assert.equal(ops.TRON_TIMELOCK_RUNTIME_KECCAK,
    '0xfcb7fa62daf40b0560729beb39f3ca1d9224ed0bba6c079b6fd2cab25fc55d5b');
  const built = path.join(__dirname, '..', 'tron', 'build', 'contracts', 'TimelockController.json');
  if (fs.existsSync(built)) {
    const code = JSON.parse(fs.readFileSync(built, 'utf8')).deployedBytecode;
    assert.equal(tw.utils.ethersUtils.keccak256(code.startsWith('0x') ? code : '0x' + code),
      ops.TRON_TIMELOCK_RUNTIME_KECCAK);
  }
  assert.equal(ops.TRON_ZERO_BASE58, ZERO);
  assert.equal(tw.address.toHex(ZERO), ops.TRON_ZERO_HEX);
});

test('checkTimelockTarget accepts the compliant timelock', async () => {
  const tw = stubbed(compliant());
  const got = await ops.checkTimelockTarget(tw, { timelock: TIMELOCK, adminMultisig: ADMIN_MS, signer: SIGNER });
  assert.equal(got.delay, 172_800n);
});

test('checkTimelockTarget refuses each unsafe timelock', async () => {
  const cases = [
    [(s) => { s.code = ''; }, /no code/],
    [(s) => { s.code = TIMELOCK_CODE.replace(/.$/, (c) => (c === '0' ? '1' : '0')); }, /code hash/],
    [(s) => { s.delay = 86_399; }, /86400/],
    [(s) => { s.roles[role('PROPOSER_ROLE')] = [PAUSE_MS]; }, /PROPOSER_ROLE/],
    [(s) => { s.roles[role('EXECUTOR_ROLE')] = [PAUSE_MS]; }, /EXECUTOR_ROLE/],
    [(s) => { s.roles[role('EXECUTOR_ROLE')].push(ZERO); }, /anyone/],
    [(s) => { s.roles[role('DEFAULT_ADMIN_ROLE')].push(SIGNER); }, /signer .* DEFAULT_ADMIN_ROLE/],
    [(s) => { s.roles[role('PROPOSER_ROLE')].push(SIGNER); }, /signer .* PROPOSER_ROLE/],
    [(s) => { s.roles[role('EXECUTOR_ROLE')].push(SIGNER); }, /signer .* EXECUTOR_ROLE/],
    [(s) => { s.roles[role('CANCELLER_ROLE')].push(SIGNER); }, /signer .* CANCELLER_ROLE/],
  ];
  for (const [mutate, want] of cases) {
    const s = compliant();
    mutate(s);
    await assert.rejects(
      ops.checkTimelockTarget(stubbed(s), { timelock: TIMELOCK, adminMultisig: ADMIN_MS, signer: SIGNER }), want);
  }
});

test('transfer-admin requires --admin-multisig and runs the timelock checks before building', async () => {
  const s = compliant();
  let tw = stubbed(s);
  await assert.rejects(ops.governance(tw, 'transfer-admin', [TIMELOCK], KEY), /--admin-multisig/);
  assert.equal(tw.built.length, 0);
  s.roles[role('PROPOSER_ROLE')].push(SIGNER);
  tw = stubbed(s);
  await assert.rejects(ops.governance(tw, 'transfer-admin', [TIMELOCK, '--admin-multisig', ADMIN_MS], KEY),
    /PROPOSER_ROLE/);
  assert.equal(tw.built.length, 0, 'nothing built for an unsafe timelock');
  tw = stubbed(compliant());
  await ops.governance(tw, 'transfer-admin', [TIMELOCK, '--admin-multisig', ADMIN_MS], KEY);
  assert.equal(tw.built.length, 1);
  assert.equal(tw.built[0].fn, 'transferAdmin(address)');
  assert.equal(tw.built[0].params[0].value, TIMELOCK);
});

test('encodes the bridge admin calls the timelock may schedule', () => {
  const tw = new TronWeb({ fullHost: 'http://127.0.0.1:1' });
  const iface = new tw.utils.ethersUtils.Interface([
    'function setToken(address,bool,uint256,uint256)', 'function unpause()',
    'function setProtocolFee(uint16)', 'function withdrawFees(address,address,uint256)',
    'function setPauser(address)', 'function transferAdmin(address)', 'function acceptAdmin()']);
  const evm = (a) => '0x' + tw.address.toHex(a).slice(2);
  const usdt = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
  assert.equal(ops.encodeBridgeCall(tw, 'setToken', [usdt, 'true', '1000', '0']),
    iface.encodeFunctionData('setToken', [evm(usdt), true, 1000, 0]));
  assert.equal(ops.encodeBridgeCall(tw, 'unpause', []), iface.encodeFunctionData('unpause', []));
  assert.equal(ops.encodeBridgeCall(tw, 'setProtocolFee', ['25']), iface.encodeFunctionData('setProtocolFee', [25]));
  assert.equal(ops.encodeBridgeCall(tw, 'withdrawFees', [usdt, PAUSE_MS, '7']),
    iface.encodeFunctionData('withdrawFees', [evm(usdt), evm(PAUSE_MS), 7]));
  assert.equal(ops.encodeBridgeCall(tw, 'setPauser', [PAUSE_MS]), iface.encodeFunctionData('setPauser', [evm(PAUSE_MS)]));
  assert.equal(ops.encodeBridgeCall(tw, 'transferAdmin', [ADMIN_MS]),
    iface.encodeFunctionData('transferAdmin', [evm(ADMIN_MS)]));
  assert.equal(ops.ACCEPT_ADMIN, iface.encodeFunctionData('acceptAdmin', []));
  assert.throws(() => ops.encodeBridgeCall(tw, 'lock', []), /--call/);
  assert.throws(() => ops.encodeBridgeCall(tw, 'setProtocolFee', []), /1 argument/);
  assert.throws(() => ops.encodeBridgeCall(tw, 'setToken', [usdt, 'yes', '1', '0']), /bool/);
  assert.throws(() => ops.encodeBridgeCall(tw, 'setProtocolFee', ['-1']), /integer/);
  assert.throws(() => ops.encodeBridgeCall(tw, 'setPauser', ['0x12']), /Tron address/);
});

test('pause --from builds an unsigned pause() from the pause multisig and writes it', async () => {
  const out = tmp();
  const tw = stubbed(compliant());
  await ops.governance(tw, 'pause', ['--from', PAUSE_MS, '--out-dir', out], '');
  assert.equal(tw.built.length, 1);
  assert.equal(tw.built[0].fn, 'pause()');
  assert.equal(tw.built[0].from, PAUSE_MS);
  assert.equal(tw.built[0].options.permissionId, 2);
  const file = JSON.parse(fs.readFileSync(path.join(out, 'tron-pause.json'), 'utf8'));
  assert.match(file.signers, /UNSIGNED/);
  // Only the pauser can pause through a multisig transaction.
  await assert.rejects(ops.governance(stubbed(compliant()), 'pause', ['--from', ADMIN_MS, '--out-dir', out], ''),
    /not the bridge pauser/);
});

test('timelock-schedule builds schedule(bridge, 0, <call>, 0, salt, delay) from a proposer', async () => {
  const out = tmp();
  const s = compliant();
  s.admin = TIMELOCK; // after the handover
  const tw = stubbed(s);
  await ops.governance(tw, 'timelock-schedule',
    [TIMELOCK, '--from', ADMIN_MS, '--call', 'setProtocolFee', '--args', '25', '--out-dir', out], '');
  assert.equal(tw.built.length, 1);
  const b = tw.built[0];
  assert.equal(b.fn, 'schedule(address,uint256,bytes,bytes32,bytes32,uint256)');
  assert.equal(b.contract, TIMELOCK);
  assert.equal(b.from, ADMIN_MS);
  assert.equal(b.params[0].value, BRIDGE);
  assert.equal(b.params[2].value, ops.encodeBridgeCall(tw, 'setProtocolFee', ['25']));
  assert.equal(b.params[5].value, '172800');
  assert.ok(fs.existsSync(path.join(out, 'tron-schedule-setProtocolFee.json')));
  // Not a proposer; or the timelock is not (yet) the bridge admin.
  await assert.rejects(ops.governance(stubbed(s), 'timelock-schedule',
    [TIMELOCK, '--from', PAUSE_MS, '--call', 'unpause', '--out-dir', out], ''), /PROPOSER_ROLE/);
  await assert.rejects(ops.governance(stubbed(compliant()), 'timelock-schedule',
    [TIMELOCK, '--from', ADMIN_MS, '--call', 'unpause', '--out-dir', out], ''), /not the timelock/);
});

test('timelock-execute refuses an operation that is not pending, and builds execute otherwise', async () => {
  const out = tmp();
  const s = compliant();
  s.admin = TIMELOCK;
  s.pending = false;
  await assert.rejects(ops.governance(stubbed(s), 'timelock-execute',
    [TIMELOCK, '--from', ADMIN_MS, '--call', 'unpause', '--out-dir', out], ''), /not pending/);
  s.pending = true;
  s.ready = true;
  const tw = stubbed(s);
  await ops.governance(tw, 'timelock-execute',
    [TIMELOCK, '--from', ADMIN_MS, '--call', 'unpause', '--out-dir', out], '');
  assert.equal(tw.built[0].fn, 'execute(address,uint256,bytes,bytes32,bytes32)');
  assert.equal(tw.built[0].params[2].value, ops.encodeBridgeCall(tw, 'unpause', []));
  assert.ok(fs.existsSync(path.join(out, 'tron-execute-unpause.json')));
});

test('multisigPermissions: owner and active id 2 need the thresholds, active may only call contracts', () => {
  const tw = new TronWeb({ fullHost: 'http://127.0.0.1:1' });
  const signers = ['33', '44', '55', '66', '77'].map((b) => b58(b.repeat(20)));
  const { owner, actives } = ops.multisigPermissions(tw, b58('99'.repeat(20)), signers, 3, 2);
  assert.deepEqual([owner.type, owner.threshold, owner.keys.length], [0, 3, 5]);
  assert.equal(actives.length, 1);
  assert.deepEqual([actives[0].type, actives[0].threshold], [2, 2]);
  // TriggerSmartContract (31) only: byte 3, bit 7. Tron's default active mask sets it too.
  assert.equal(actives[0].operations, '00000080' + '00'.repeat(28));
  assert.ok(owner.keys.every((k) => k.weight === 1));
  assert.ok(tw.transactionBuilder.checkPermissions(owner, 0) && tw.transactionBuilder.checkPermissions(actives[0], 2));
});

test('multisigPermissions refuses a weak or self-including set', () => {
  const tw = new TronWeb({ fullHost: 'http://127.0.0.1:1' });
  const account = b58('99'.repeat(20));
  const signers = ['33', '44', '55'].map((b) => b58(b.repeat(20)));
  assert.throws(() => ops.multisigPermissions(tw, account, signers, 1, 2), /owner-threshold/);
  assert.throws(() => ops.multisigPermissions(tw, account, signers, 2, 4), /active-threshold/);
  assert.throws(() => ops.multisigPermissions(tw, account, [signers[0], signers[0]], 2, 2), /duplicate/);
  assert.throws(() => ops.multisigPermissions(tw, account, [...signers, account], 2, 2), /itself/);
  assert.throws(() => ops.multisigPermissions(tw, account, [signers[0]], 2, 2), /at least two/);
});
