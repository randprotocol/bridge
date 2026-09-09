// Deploys TronRandBridge (chain id 4 in the bridge registry) to whichever
// network `tronbox migrate --network <name>` targets.
//
// Required environment variables (see tron/README.md):
//   ADMIN         Tron or EVM-style address of the multisig that owns the
//                  token whitelist (base58 "T..." or hex, 0x/41-prefixed
//                  or bare).
//   PAUSER         Tron or EVM-style address of the pause quorum. The base
//                  Foundry deploy script (evm/script/Deploy.s.sol) lets this
//                  default to the zero address; this migration requires it
//                  explicitly so a Tron deployment never silently ships
//                  without a pauser.
//   RAND_EMITTER   0x-prefixed 32-byte hex string: the Rand burn emitter
//                  address from genesis (bridge.emitter).
//   GUARDIANS      Comma-separated list of guardian addresses (index order
//                  == guardian set index order), each base58 "T...", or hex
//                  (0x/41-prefixed or bare 20-byte Ethereum-style).
//
// Every address is normalised to Tron's 21-byte "41..."-prefixed hex form
// with `tronWeb.address.toHex` before being handed to the constructor,
// exactly as TronRandBridge's constructor signature
// (address admin_, address pauser_, bytes32 randEmitter_, address[] guardians)
// expects (see evm/src/RandBridgeBase.sol and evm/src/TronRandBridge.sol).

const TronRandBridge = artifacts.require('TronRandBridge');

function requireEnv(name) {
  const value = process.env[name];
  if (value === undefined || value === null || value.trim() === '') {
    throw new Error(
      `tron/migrations/2_deploy.js: missing required environment variable ${name}. ` +
        'See tron/README.md for the full list (ADMIN, PAUSER, RAND_EMITTER, GUARDIANS).'
    );
  }
  return value.trim();
}

// Accepts a Tron base58check address ("T...") or a hex address, either
// Tron-style (41-prefixed, 21 bytes) or Ethereum-style (20 bytes, with or
// without a "0x" prefix -- guardian keys in particular are plain
// keccak256-derived Ethereum-style addresses, per Attestation.sol), and
// normalises it to the 21-byte "41..." hex form tronWeb/TronBox expect for
// a Solidity `address` constructor argument.
function toTronHexAddress(value, label) {
  const raw = value.trim();

  // Base58check Tron address.
  if (/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(raw)) {
    return tronWeb.address.toHex(raw);
  }

  let hex = raw.startsWith('0x') || raw.startsWith('0X') ? raw.slice(2) : raw;
  if (hex.length === 40) {
    // Bare 20-byte Ethereum-style address (e.g. a guardian key): prepend
    // Tron's "41" address-version prefix.
    hex = '41' + hex;
  }
  if (!/^41[0-9a-fA-F]{40}$/.test(hex)) {
    throw new Error(`tron/migrations/2_deploy.js: ${label} is not a valid Tron or hex address: ${value}`);
  }
  // Round-trip through tronWeb so the result is exactly the form TronBox's
  // deployer expects, whichever accepted form we were given.
  return tronWeb.address.toHex(hex);
}

module.exports = function (deployer) {
  const adminEnv = requireEnv('ADMIN');
  const pauserEnv = requireEnv('PAUSER');
  const randEmitterEnv = requireEnv('RAND_EMITTER');
  const guardiansEnv = requireEnv('GUARDIANS');

  if (!/^0x[0-9a-fA-F]{64}$/.test(randEmitterEnv)) {
    throw new Error(
      `tron/migrations/2_deploy.js: RAND_EMITTER must be a 0x-prefixed 32-byte (64 hex char) string, got: ${randEmitterEnv}`
    );
  }

  const admin = toTronHexAddress(adminEnv, 'ADMIN');
  const pauser = toTronHexAddress(pauserEnv, 'PAUSER');
  const guardians = guardiansEnv
    .split(',')
    .map((g) => g.trim())
    .filter((g) => g.length > 0)
    .map((g, i) => toTronHexAddress(g, `GUARDIANS[${i}]`));

  if (guardians.length === 0) {
    throw new Error('tron/migrations/2_deploy.js: GUARDIANS must list at least one guardian address');
  }

  console.log('admin       ', admin);
  console.log('pauser      ', pauser);
  console.log('randEmitter ', randEmitterEnv);
  console.log('guardians   ', guardians);

  deployer.deploy(TronRandBridge, admin, pauser, randEmitterEnv, guardians);
};
