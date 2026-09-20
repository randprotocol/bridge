#!/usr/bin/env node
// Post-deployment operations on the Tron endpoint. The signing key comes from the
// OPS_PRIVATE_KEY environment variable only — never from the command line.
//
//   OPS_PRIVATE_KEY=... node deploy/tron-ops.js fund <to> <sun>
//   OPS_PRIVATE_KEY=... node deploy/tron-ops.js set-token <bridge> <token> <perTransferCap> <dailyCap>
//   OPS_PRIVATE_KEY=... node deploy/tron-ops.js lock <bridge> <token> <amount> <recipientHash hex32> <relayerFee> <nonce>
//                       node deploy/tron-ops.js token-config <bridge> <token>
//
// Addresses are base58 (T...). TRON_RPC_URL overrides https://api.trongrid.io; TronWeb is the
// copy `deploy/trx.sh` installs into tron/node_modules.
const path = require('path');
const { TronWeb } = require(path.join(__dirname, '..', 'tron', 'node_modules', 'tronweb'));

const FEE_LIMIT = 100_000_000; // 100 TRX

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
    throw new Error('usage: fund | set-token | lock | token-config');
  }
}

main().catch((e) => { console.error(e.message || e); process.exit(1); });
