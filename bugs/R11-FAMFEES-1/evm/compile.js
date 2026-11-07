const solc = require('../../evm/node_modules/solc'); const fs = require('fs'); const path = require('path');
const OZ = path.join(__dirname, '../oz/package/'); const PRT = path.join(__dirname, '../dave/prt/contracts/src/');
function find(p) {
  let f;
  if (p.startsWith('@openzeppelin-contracts-5.5.0/')) f = OZ + p.slice('@openzeppelin-contracts-5.5.0/'.length);
  else if (p.startsWith('prt-contracts/')) f = PRT + p.slice('prt-contracts/'.length);
  else f = path.join(__dirname, p);
  try { return { contents: fs.readFileSync(f, 'utf8') }; } catch (e) { return { error: 'not found ' + f }; }
}
const input = { language: 'Solidity', sources: { 'Maker.sol': { content: fs.readFileSync(path.join(__dirname, 'Maker.sol'), 'utf8') } },
  settings: { viaIR: true, optimizer: { enabled: true, runs: 200 }, evmVersion: 'prague',
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.methodIdentifiers'] } } } };
const out = JSON.parse(solc.compile(JSON.stringify(input), { import: find }));
let bad = false;
if (out.errors) for (const e of out.errors) if (e.severity === 'error') { console.log(e.formattedMessage); bad = true; }
if (bad) process.exit(1);
const T = out.contracts['prt-contracts/tournament/Tournament.sol'].Tournament, M = out.contracts['Maker.sol'].Maker;
fs.writeFileSync(path.join(__dirname, 'build.json'), JSON.stringify({ T: { abi: T.abi, bin: T.evm.bytecode.object, ids: T.evm.methodIdentifiers }, M: { abi: M.abi, bin: M.evm.bytecode.object, ids: M.evm.methodIdentifiers } }));
console.log('ok', T.evm.bytecode.object.length / 2, M.evm.bytecode.object.length / 2);
