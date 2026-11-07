const solc = require('solc'); const fs = require('fs'); const path=require('path');
const dir = path.join(__dirname,'sol'); const sources={};
for (const f of fs.readdirSync(dir)) if (f.endsWith('.sol')) sources[f]={content:fs.readFileSync(path.join(dir,f),'utf8')};
const input={language:'Solidity',sources,settings:{optimizer:{enabled:true,runs:200},viaIR:false,evmVersion:'shanghai',outputSelection:{'Harness.sol':{Harness:['abi','evm.bytecode.object','evm.deployedBytecode.object','evm.methodIdentifiers']}}}};
const out=JSON.parse(solc.compile(JSON.stringify(input)));
if (out.errors) for (const e of out.errors) if (e.severity==='error') console.log(e.formattedMessage);
const c=out.contracts['Harness.sol'].Harness;
fs.writeFileSync(path.join(__dirname,'harness.json'),JSON.stringify({abi:c.abi,bytecode:c.evm.bytecode.object,deployed:c.evm.deployedBytecode.object,ids:c.evm.methodIdentifiers}));
console.log('deployed size', c.evm.deployedBytecode.object.length/2);
