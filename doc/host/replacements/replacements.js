const fs = require('fs');

function findAllHashes(output) {
    var ret = [];
    output.replace(/(\d+): ([a-fA-F0-9]{64})/g, function(m, c, h) { ret.push({"cycles": c, "hash": h}) })
    return ret;
}

function findAllCycles(output) {
    var ret = [];
    output.replace(/Cycles: (\d+)/g, function(m, c) { ret.push(c) })
    return ret;
}

module.exports.run = async function() {
    await generateOutput(__dirname, "machine.host.lua.config-dump-ls-bin");
    const dumpConfigNothing = await generateOutput(__dirname, "machine.host.lua.config-dump-nothing");
    const configNothing = dumpConfigNothing.replace("machine_config = {", "return {").replace("Cycles: 0\n","");
    const mvendorid = findLuaValue(dumpConfigNothing, "mvendorid");
    const mimpid = findLuaValue(dumpConfigNothing, "mimpid");
    const marchid = findLuaValue(dumpConfigNothing, "marchid");
    replacements["machine.host.lua.config-mvendorid"] = mvendorid;
    replacements["machine.host.lua.config-mimpid"] = mimpid;
    replacements["machine.host.lua.config-marchid"] = marchid;
    fs.writeFileSync(`${__dirname}/config-nothing-to-do.lua`, configNothing);

    // cmdline limit exec and state hashes
    const cyclesLimitExec = await generateOutput(__dirname, "machine.host.cmdline.cycles-limit-exec");
    await generateOutput(__dirname, "machine.host.cmdline.limit-exec", cyclesLimitExec);

    await generateOutput(__dirname, "machine.host.cmdline.rolling-ioctl-echo-loop");
    delete replacements["machine.host.cmdline.rolling-ioctl-echo-loop"]
    var client = fs.readFileSync(`${__dirname}/client.out`, {encoding:'utf8', flag:'r'});
    var hashes = findAllHashes(client);
    var cycles = findAllCycles(client);
    replacements["machine.host.cmdline.rolling-ioctl-echo-loop-client"] = client
    replacements["machine.host.cmdline.rolling-ioctl-echo-loop-0client"] = client.split("\n").slice(0, 5).join("\n");
    replacements["machine.host.cmdline.rolling-ioctl-echo-loop-1client"] = client.split("\n").slice(7, 28).join("\n");
    replacements["machine.host.cmdline.rolling-ioctl-echo-loop-2client"] = client.split("\n").slice(30, 52).join("\n");
    replacements["machine.host.cmdline.rolling-ioctl-echo-loop-3client"] = client.split("\n").slice(53, 63).join("\n");

    var i = 0
    for (var x of hashes) {
        replacements["machine.host.cmdline.rolling-ioctl-echo-loop-hashes" + i] = truncateHash(x["hash"]);
        i++;
    }
    i = 0;
    for (var x of cycles) {
        replacements["machine.host.cmdline.rolling-ioctl-echo-loop-cycles" + i] = x;
        i++;
    }
    var server = fs.readFileSync(`${__dirname}/server.out`, {encoding:'utf8', flag:'r'});
    replacements["machine.host.cmdline.rolling-ioctl-echo-loop-server"] = server
    fs.unlinkSync(`${__dirname}/client.out`);
    fs.unlinkSync(`${__dirname}/server.out`);

    await generateOutput(__dirname, "machine.host.cmdline.rolling-calc-template");
    delete replacements["machine.host.cmdline.rolling-calc-template"];
    replacements["machine.host.cmdline.rolling-calc-template.template"] =
        fs.readFileSync(`${__dirname}/template.out`, {encoding:'utf8', flag:'r'});
    replacements["machine.host.cmdline.rolling-calc-template.server"] =
        fs.readFileSync(`${__dirname}/server.out`, {encoding:'utf8', flag:'r'});
    replacements["machine.host.cmdline.rolling-calc-template.client"] =
        fs.readFileSync(`${__dirname}/client.out`, {encoding:'utf8', flag:'r'});
    fs.unlinkSync(`${__dirname}/template.out`);
    fs.unlinkSync(`${__dirname}/client.out`);
    fs.unlinkSync(`${__dirname}/server.out`);
    replacements["machine.host.cmdline.rolling-calc-sh"] = fs.readFileSync(`${__dirname}/calc.sh`, {encoding:'utf8', flag:'r'});

    await generateOutput(__dirname, "machine.host.cmdline.remote");
    delete replacements["machine.host.cmdline.remote"]
    var client = fs.readFileSync(`${__dirname}/client.out`, {encoding:'utf8', flag:'r'});
    var server = fs.readFileSync(`${__dirname}/server.out`, {encoding:'utf8', flag:'r'});
    fs.unlinkSync(`${__dirname}/client.out`);
    fs.unlinkSync(`${__dirname}/server.out`);
    replacements["machine.host.cmdline.remote-client"] = client;
    replacements["machine.host.cmdline.remote-server"] = server;

    await generateOutput(__dirname, "machine.host.cmdline.remote-begin");
    delete replacements["machine.host.cmdline.remote-begin"]
    var client = fs.readFileSync(`${__dirname}/client.out`, {encoding:'utf8', flag:'r'});
    fs.unlinkSync(`${__dirname}/client.out`);
    fs.unlinkSync(`${__dirname}/server.out`);
    replacements["machine.host.cmdline.remote-begin-client"] = client;

    await generateOutput(__dirname, "machine.host.cmdline.remote-end");
    delete replacements["machine.host.cmdline.remote-end"]
    var client = fs.readFileSync(`${__dirname}/client.out`, {encoding:'utf8', flag:'r'});
    var server = fs.readFileSync(`${__dirname}/server.out`, {encoding:'utf8', flag:'r'});
    fs.unlinkSync(`${__dirname}/client.out`);
    fs.unlinkSync(`${__dirname}/server.out`);
    replacements["machine.host.cmdline.remote-end-client"] = client;
    replacements["machine.host.cmdline.remote-begin-end-server"] = server;

    // overview
    await generateOutput(__dirname, "machine.host.overview.help");
    await generateOutput(__dirname, "machine.host.overview.sha256-linux");
    await generateOutput(__dirname, "machine.host.overview.sha256-rom");
    await generateOutput(__dirname, "machine.host.overview.sha256-rootfs");

    // cmdline
    await generateOutput(__dirname, "machine.host.cmdline.interactive-ls");
    await generateOutput(__dirname, "machine.host.cmdline.ls");
    await generateOutput(__dirname, "machine.host.cmdline.nothing");
    await generateOutput(__dirname, "machine.host.cmdline.flash");
    await generateOutput(__dirname, "machine.host.cmdline.persistent-flash");

    const stateHashesLimitExec = await generateOutput(__dirname, "machine.host.cmdline.state-hashes-limit-exec", cyclesLimitExec);
    replacements["machine.host.cmdline.state-hashes-initial"] = truncateHash(findHash(stateHashesLimitExec, "0"));
    replacements["machine.host.cmdline.state-hashes-final-limit-exec"] = truncateHash(findHash(stateHashesLimitExec, cyclesLimitExec));

    const stateHashesNoLimit = await generateOutput(__dirname, "machine.host.cmdline.state-hashes-no-limit");
    const stateHashesCyclesNoLimit = findCycles(stateHashesNoLimit);
    replacements["machine.host.cmdline.state-hashes-cycles-no-limit"] = stateHashesCyclesNoLimit;
    replacements["machine.host.cmdline.state-hashes-final-no-limit"] = truncateHash(findHash(stateHashesNoLimit, stateHashesCyclesNoLimit));

    await generateOutput(__dirname, "machine.host.cmdline.persistent-machine", cyclesLimitExec);
    await generateOutput(__dirname, "machine.host.cmdline.persistent-stored-hash", cyclesLimitExec);

    // cmdline templates
    await generateOutput(__dirname, "machine.host.cmdline.templates-run");
    await generateOutput(__dirname, "machine.host.cmdline.templates-store");
    const templatesHash = await generateOutput(__dirname, "machine.host.cmdline.templates-hash");
    replacements["machine.host.cmdline.templates-trunc-hash"] = truncateHash(templatesHash);

    // cmdline proofs
    await generateOutput(__dirname, "machine.host.cmdline.proofs-pristine-run");
    await generateOutput(__dirname, "machine.host.cmdline.proofs-pristine-json");
    const proofsInput = await generateOutput(__dirname, "machine.host.cmdline.proofs-input-json");
    replacements["machine.host.cmdline.proofs-input-roothash"] = truncateHash(findHash(proofsInput, "root_hash"));
    const proofsOutputRun = await generateOutput(__dirname, "machine.host.cmdline.proofs-output-run");
    const proofsOutputRunCycles = findCycles(proofsOutputRun);
    const proofsOutput = await generateOutput(__dirname, "machine.host.cmdline.proofs-output-json");
    replacements["machine.host.cmdline.proofs-output-roothash"] = truncateHash(findHash(proofsOutput, "root_hash"));

    // cmdline rarely
    await generateOutput(__dirname, "machine.host.cmdline.rarely-append-bootargs-loglevel");
    await generateOutput(__dirname, "machine.host.cmdline.rarely-id");
    await generateOutput(__dirname, "machine.host.cmdline.rarely-append-bootargs-single-id");
    await generateOutput(__dirname, "machine.host.cmdline.default-rom-bootargs");
    const periodicInitialCycle = proofsOutputRunCycles - 10;
    replacements["machine.host.cmdline.rarely-periodic-initial-cycle"] = periodicInitialCycle
    await generateOutput(__dirname, "machine.host.cmdline.rarely-periodic-hashes", periodicInitialCycle);
    await generateOutput(__dirname, "machine.host.cmdline.rarely-step", cyclesLimitExec);

    // lua
    await generateOutput(__dirname, "machine.host.lua.state-hashes-lua", "config-nothing-to-do");
    await generateOutput(__dirname, "machine.host.lua.state-hashes-utility");
    await generateOutput(__dirname, "machine.host.lua.state-transition-dump-step", `config-nothing-to-do ${cyclesLimitExec}`);
    fs.unlinkSync(`${__dirname}/config-nothing-to-do.lua`);

    await generateOutput(__dirname, "machine.host.lua.remote");
    delete replacements["machine.host.lua.remote"]
    client = fs.readFileSync(`${__dirname}/client.out`, {encoding:'utf8', flag:'r'});
    server = fs.readFileSync(`${__dirname}/server.out`, {encoding:'utf8', flag:'r'});
    fs.unlinkSync(`${__dirname}/client.out`);
    fs.unlinkSync(`${__dirname}/server.out`);
    replacements["machine.host.lua.remote-client"] = client;
    replacements["machine.host.lua.remote-server"] = server;
}

