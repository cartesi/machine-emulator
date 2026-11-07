// Measures, on the pinned PRT Tournament.sol (Dave v3.0.0-alpha.6, solc 0.8.30 viaIR runs 200, OpenZeppelin 5.5.0;
// compiled artifacts in build.json, built by compile.js), the gas that joinTournament and winMatchByTimeout need
//   (a) when the tournament holds no dangling commitment (the state the bridge's eth_estimateGas sees), and
//   (b) when a Sybil joined first, so the honest call takes the pairing branch (Match.create).
// "Needed" is the minimal transaction gas limit at which the call succeeds (what eth_estimateGas converges to).
// It then runs the honest transaction in state (b) with exactly the limit the bridge signs: ceil(1.2 * (a)).
// Usage: NM=/path/to/node_modules node measure.mjs   -> JSON on stdout.
import fs from 'fs';
import path from 'path';
import { pathToFileURL } from 'url';
const NM = process.env.NM || new URL('./node_modules', import.meta.url).pathname;
const imp = (p) => import(pathToFileURL(path.join(NM, p)).href);
const { EVM } = await imp('@ethereumjs/evm/dist/esm/index.js');
const { Common } = await imp('@ethereumjs/evm/node_modules/@ethereumjs/common/dist/esm/index.js');
const U = await imp('@ethereumjs/evm/node_modules/@ethereumjs/util/dist/esm/index.js');
const { keccak256 } = await imp('ethereum-cryptography/keccak.js');
const { Address, hexToBytes, bytesToHex } = U;
const B = JSON.parse(fs.readFileSync(new URL('./build.json', import.meta.url)));
const sel = (s) => bytesToHex(keccak256(new TextEncoder().encode(s))).slice(2, 10);
const w = (x) => (typeof x === 'bigint' || typeof x === 'number' ? BigInt(x).toString(16) : x.replace(/^0x/, '')).padStart(64, '0');
const H2 = (a, b) => bytesToHex(keccak256(hexToBytes('0x' + w(a) + w(b))));
const addr = (n) => new Address(hexToBytes('0x' + n.toString(16).padStart(40, '0')));
const LEVEL = 0n, ALLOW = 5000n, RB = 10n;
const claimFor = (HEIGHT) => (seed) => { // commitment whose last leaf is finalState, with the proof joinTournament checks
  const fs_ = H2(seed, 0xf1n); const sib = []; let node = fs_;
  for (let i = 0n; i < HEIGHT; i++) { const s = H2(seed, 0x1000n + i); sib.push(s); if (i < HEIGHT - 1n) node = H2(s, node); }
  const left = sib[sib.length - 1], right = node; return { fs: fs_, sib, left, right, root: H2(left, right) };
};
const joinData = (c) => '0x' + sel('joinTournament(bytes32,bytes32[],bytes32,bytes32)') + w(c.fs) + w(0x80n) + w(c.left) + w(c.right) + w(BigInt(c.sib.length)) + c.sib.map(w).join('');
const timeoutData = (one, two, c) => '0x' + sel('winMatchByTimeout((bytes32,bytes32),bytes32,bytes32)') + w(one) + w(two) + w(c.left) + w(c.right);
function intrinsic(data) {
  const b = hexToBytes(data); let z = 0, nz = 0; for (const x of b) x ? nz++ : z++;
  const tokens = z + 4 * nz; return { std: 21000 + 4 * tokens, floor: 21000 + 10 * tokens };
}
const blk = (n) => ({ header: { number: BigInt(n), cliqueSigner: () => new Address(new Uint8Array(20)), coinbase: new Address(new Uint8Array(20)), timestamp: BigInt(n) * 12n,
  difficulty: 0n, prevRandao: new Uint8Array(32), gasLimit: 60000000n, baseFeePerGas: 1n, getBlobGasPrice: () => 1n } });
const ok = (r) => !r.execResult.exceptionError;
async function world(HEIGHT) {
  const evm = await EVM.create({ common: new Common({ chain: 'mainnet', hardfork: 'cancun' }), allowUnlimitedContractSize: true });
  for (let i = 1; i <= 20; i++) await evm.stateManager.putAccount(addr(i), new U.Account(0n, 10n ** 27n));
  const call = (from, to, data, value = 0n, gas = 30000000n, n = 100) =>
    evm.runCall({ caller: addr(from), to, data: hexToBytes(data), value, gasLimit: gas, block: blk(n), origin: addr(from), gasPrice: 1n });
  const d1 = await evm.runCall({ caller: addr(1), data: hexToBytes('0x' + B.T.bin), gasLimit: 100000000n, block: blk(1) });
  const d2 = await evm.runCall({ caller: addr(1), data: hexToBytes('0x' + B.M.bin), gasLimit: 100000000n, block: blk(1) });
  if (d1.execResult.exceptionError || d2.execResult.exceptionError) throw new Error('deploy');
  const impl = d1.createdAddress, maker = d2.createdAddress;
  const mk = '0x' + B.M.ids['make(address,uint64,uint8,uint64,uint64,uint64,uint64,bytes32,bytes32,bytes32,bytes32)'] +
    w(impl.toString()) + w(LEVEL) + w(0n) + w(HEIGHT) + w(0n) + w(ALLOW) + w(RB) + w(0n) + w(0n) + w(0n) + w(0n);
  const r = await call(1, maker, mk, 0n, 30000000n, 100);
  if (r.execResult.exceptionError) throw new Error('make');
  const t = new Address(r.execResult.returnValue.slice(12));
  const bond = BigInt(bytesToHex((await call(1, t, '0x' + B.T.ids['bondValue()'])).execResult.returnValue));
  return { call, t, bond };
}
// Minimal transaction gas limit for the last call of a scenario, like eth_estimateGas.
async function estimate(HEIGHT, setup, last) {
  let lo = 21000n, hi = 30000000n;
  const probe = async (g) => { const W = await world(HEIGHT); await setup(W); const { from, data, value, n } = last(W);
    const i = intrinsic(data); const exec = g - BigInt(i.std); if (g < BigInt(i.floor) || exec < 0n) return false;
    return ok(await W.call(from, W.t, data, value, exec, n)); };
  if (!(await probe(hi))) return null;
  while (hi - lo > 1n) { const m = (lo + hi) / 2n; if (await probe(m)) hi = m; else lo = m; }
  return { gas: hi, probe };
}
const out = [];
for (const HEIGHT of [30n, 62n]) {
  const claim = claimFor(HEIGHT), A = claim(0xa1n), H = claim(0x401n), S = claim(0x5bn);
  // joinTournament: honest join with no dangling commitment (estimate) vs. a Sybil joined first (inclusion).
  {
    const join = (W, c, from) => ({ from, data: joinData(c), value: W.bond, n: 120 });
    const sybil = async (W) => { if (!ok(await W.call(3, W.t, joinData(S), W.bond, 30000000n, 110))) throw new Error('sybil'); };
    const e0 = await estimate(HEIGHT, async () => {}, (W) => join(W, H, 2));
    const e1 = await estimate(HEIGHT, sybil, (W) => join(W, H, 2));
    const signed = (e0.gas * 12n + 9n) / 10n; // prt-transactions.lua:214
    const W = await world(HEIGHT); await sybil(W);
    const d = joinData(H); const r = await W.call(2, W.t, d, W.bond, signed - BigInt(intrinsic(d).std), 120);
    const rn = await W.call(2, W.t, d, W.bond, e1.gas - BigInt(intrinsic(d).std), 120);
    out.push({ name: 'joinTournament', height: Number(HEIGHT), estimate_no_dangling: Number(e0.gas), bridge_gas_limit: Number(signed),
      needed_after_sybil_join: Number(e1.gas), honest_tx_with_bridge_gas_after_sybil_join: ok(r) ? 'success' : 'reverted',
      honest_tx_with_needed_gas_after_sybil_join: ok(rn) ? 'success' : 'reverted' });
  }
  // winMatchByTimeout: A vs H match, A (responder) lets its clock run out; H wins by timeout.
  {
    const base = async (W) => { for (const [c, f] of [[A, 4], [H, 2]]) { const r = await W.call(f, W.t, joinData(c), W.bond, 30000000n, 110); if (!ok(r)) throw new Error('join'); } };
    const win = () => ({ from: 2, data: timeoutData(A.root, H.root, H), value: 0n, n: 110 + Number(ALLOW) + 50 });
    const sybil = async (W) => { await base(W); if (!ok(await W.call(3, W.t, joinData(S), W.bond, 30000000n, 111))) throw new Error('sybil2'); };
    const e0 = await estimate(HEIGHT, base, win), e1 = await estimate(HEIGHT, sybil, win);
    if (!e0 || !e1) throw new Error('winMatchByTimeout scenario did not succeed');
    const signed = (e0.gas * 12n + 9n) / 10n;
    const W = await world(HEIGHT); await sybil(W);
    const d = timeoutData(A.root, H.root, H), n = win().n;
    const r = await W.call(2, W.t, d, 0n, signed - BigInt(intrinsic(d).std), n);
    const rn = await W.call(2, W.t, d, 0n, e1.gas - BigInt(intrinsic(d).std), n);
    out.push({ name: 'winMatchByTimeout', height: Number(HEIGHT), estimate_no_dangling: Number(e0.gas), bridge_gas_limit: Number(signed),
      needed_after_sybil_join: Number(e1.gas), honest_tx_with_bridge_gas_after_sybil_join: ok(r) ? 'success' : 'reverted',
      honest_tx_with_needed_gas_after_sybil_join: ok(rn) ? 'success' : 'reverted' });
  }
}
console.log(JSON.stringify(out));
