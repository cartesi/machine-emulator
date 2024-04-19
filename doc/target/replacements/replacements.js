module.exports.run = async function() {
    await generateOutput(__dirname, "machine.target.linux.interactive-ls");
    await generateOutput(__dirname, "machine.target.linux.hello-cpp");
    await generateOutput(__dirname, "machine.target.architecture.dtc");
}

