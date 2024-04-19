---
title: Hash view of state

---

One of the key goals of moving computations off-chain is to allow them to manipulate vast amounts of data: so much data that it becomes economically prohibitive to explicitly store them in the blockchain.
Nevertheless, for smart contracts to delegate computations off-chain, they must be able to specify the computations, their inputs, and then reason over their outputs.
The key to solving these seemingly contradictory goals is the clever use of cryptographic hashes.

Cartesi Machines are transparent in the sense that their entire state is exposed for external inspection.
This includes the ROM, the RAM, all flash drives, general purpose registers, control and status registers, and even the internal state of all devices.
In fact, the entire machine state is mapped into the 64-bit physical memory address space of the Cartesi Machine.
(The exact mapping is given in the [system architecture](../target/architecture.md) section of the target perspective.)
This means that, right before a machine is executed, a cryptographic hash of its entire state can be generated.
A cryptographic hash of the state of a Cartesi Machine &ldquo;completely&rdquo; specifies the computation it is about to perform.
This is because a given state always evolve in exactly the same way (because Cartesi Machines are self-contained and reproducible) and it is infeasible to find a different machine state that produces the same cryptographic state hash.
By the same token, once the machine is done, the state hash &ldquo;completely&rdquo; specifies the result of the computation, wherever it may reside within the address space.

:::info
The scare quotes around &ldquo;completely&rdquo; are pedantic.
It is true that there are a multitude of machine states that produce the same state hash.
After all, the Keccak-256 state hashes fit in 256-bits, whereas machine states can take gigabytes.
There are therefore many more possible machine states than possible state hashes.
By the pigeonhole principle, there must be multiple machines with the same hash (i.e., hash collisions).
However, given only the state hash, finding a Cartesi Machine with that state hash should be virtually impossible.
Given a Cartesi Machine and its state hash, finding a *second* (distinct) Cartesi Machine with the same state hash should also be virtually impossible.
Even finding two different Cartesi Machines that have the same state hash (any hash) should be virtually impossible.
Cryptographic hash functions, such as Keccak-256, were designed *specifically* to have these properties.
:::

The state hash of a Cartesi Machine is the root hash of a Merkle tree.
Merkle trees are binary trees where a leaf node is labeled with the hash of a data block (In the case of Cartesi Machines, a block is simply one of the 2<sup>61</sup> 64-bit words in the machine's physical memory address space.) and an inner node is labeled with the hash of the concatenated labels of its two child nodes.
The root hash can be obtained from the `machine:get_root_hash()` method.
In the command-line, the options `--initial-hash` and `--final-hash` of the `cartesi-machine` utility cause it to output the root hash of the Merkle tree as it is before the emulator starts running and after it is done running, respectively.

The `cartesi.keccak(<word>)` function of the `cartesi` Lua module returns the hash of a 64-bit `<word>`.
The `cartesi.keccak(<hash1>, <hash2>)` overload returns the hash of the concatenation of `<hash1>` and `<hash2>`.
In theory, the Merkle tree of the entire machine state could be built from these primitives and [external state access](../host/lua.md#external-state-access) to the machine instance.
In practice, most of the state is unused and implicitly filled with zeros, and this allows the Merkle tree computation to skip large swaths of the state by using precomputed pristine hashes of all power-of-2 sizes.
The computation is also smart enough to only update the parts of the tree that changed between invocations.

Tree hashes are used instead of a linear hashes because they support a variety of operations that are unavailable from linear hashes.

## Merkle tree operations

In the Merkle tree of a Cartesi Machine state, the labels of each the 2<sup>D</sup> nodes at a depth *D* can be seen as the root hashes for Merkle *subtrees* corresponding to adjacent intervals of *2<sup>L</sup>* bytes in the address space, where *L=64-D*.
Each of these nodes can be identified by an address *A* and the log *L* of the length of the interval it spans, where *A* is aligned to a *2<sup>L</sup>* boundary.

Consider a scenario in which a smart contract knows *only* the state hash *M* for a certain Cartesi Machine.
Using Merkle trees makes the following key operations possible:
1. *Slicing* &mdash; A user with access to the Merkle tree of *M* can provide data the blockchain can use to prove that the word at a given address has a given value. More generally, the user can provide data the blockchain can use to prove that a node with a given address and length in the tree has a given label;
1. *Splicing* &mdash; A user with access to the Merkle tree of *M* can provide data the blockchain can use to prove that writing a given word at a given address results in a Cartesi Machine with a given state hash *M'*.  More generally, the user can provide data the blockchain can use to prove that replacing a node of given length at a given address with another node of equal length and a given label results in a Cartesi Machine with a given state hash *M'*.

To understand how the slicing proof works, notice that the path from the Merkle tree node at depth *D>0* (i.e., with log length *L=64-D*) and address *A* goes through *D* nodes: *n<sub>D</sub>*, *n<sub>D-1</sub>*, &hellip;, *n<sub>1</sub>* until it reaches the root *n<sub>0</sub>*.
The labels associated to all these nodes can be produced as follows.
If *n<sub>D</sub>* is a leaf node, the word value must be provided and the label is the hash of the word value.
Otherwise, if it is a general node, its label must be provided.
The label of *n<sub>D-1</sub>* can then be obtained by hashing together the label of node *n<sub>D</sub>* and the label of its sibling.
The order between these two siblings is available from the *D*th most significant bit in address *A*.
If it is clear, *n<sub>D</sub>*'s label comes first, otherwise, its sibling's label comes first.
It should be obvious that, when labels for *all siblings* in the path from the target node to the root are provided, this process can be repeated until the label of *n<sub>0</sub>* itself is obtained.
This must match the value *M* known to the smart contract.
In fact, due to the properties of cryptographic hashes, it is infeasible for the label so obtained to match *M* *unless all the data provided is true*.

The data needed for the proofs can be produced by the `machine:get_proof(<address>, <log2-size>)` method of a Cartesi Machine instance.
The contents of the proof returned are described in the [host perspective](../host/lua.md#state-value-proofs).
The same section gives the source-code for a simple function, `roll_hash_up(<proof>, <target-hash>)`,  that implements the process described above.
Here, `<proof>` is the structure returned by the `machine:get_proof()` method.
The source-code is repeated below for convenience.

```lua title="cartesi/proof.lua (excerpt)"
local cartesi = require"cartesi"

local _M = {}

function _M.roll_hash_up_tree(proof, target_hash)
    local hash = target_hash
    for log2_size = proof.log2_target_size, proof.log2_root_size-1 do
        local bit = (proof.target_address & (1 << log2_size)) ~= 0
        local first, second
        local i = proof.log2_root_size-log2_size
        if bit then
            first, second = proof.sibling_hashes[i], hash
        else
            first, second = hash, proof.sibling_hashes[i]
        end
        hash = cartesi.keccak(first, second)
    end
    return hash
end

function _M.slice_assert(root_hash, proof)
    assert(root_hash == proof.root_hash, "proof root_hash mismatch")
    assert(_M.roll_hash_up_tree(proof, proof.target_hash) == root_hash,
        "node not in tree")
end

function _M.word_slice_assert(root_hash, proof, word)
    assert(proof.log2_target_size == 3, "not a word proof")
    assert(root_hash == proof.root_hash, "proof root_hash mismatch")
    assert(cartesi.keccak(word) == proof.target_hash, "proof target_hash mismatch")
    assert(_M.roll_hash_up_tree(proof, proof.target_hash) == root_hash,
        "node not in tree")
end

function _M.splice_assert(root_hash, proof, new_target_hash, new_root_hash)
    _M.slice_assert(root_hash, proof)
    assert(_M.roll_hash_up_tree(proof, new_target_hash) == new_root_hash,
        "new root hash mismatch")
end

function _M.word_splice_assert(root_hash, proof, old_word, new_word, new_root_hash)
    _M.word_slice_assert(root_hash, proof, old_word)
    assert(_M.roll_hash_up_tree(proof, cartesi.keccak(new_word)) == new_root_hash,
        "new root hash mismatch")
end

return _M
```
To verify a slicing operation, the code first checks the root hash *M* against the one found in the proof.
Then, it uses `roll_hash_up_tree` to recompute the root hash from the path between the target node and root.
Any mismatch triggers an assertion.

Verifying a splicing operation is just as easy.
First, the code verifies that the slicing operation is valid
This ensures that the sibling hashes are correct.
Then, it uses `roll_hash_up_tree` to compute the root hash from the path between the target node and root.
Only this time it starts from the new target node hash.
The resulting root hash is the hash of a tree with the old node replaced by the new.

### Template instantiation

The most important use for the splicing operation is template instantiation.
From the blockchain perspective, a [Cartesi Machine template](../host/cmdline.md#cartesi-machine-templates) is simply a state hash *M*.
Instantiating the Cartesi Machine with a given input is simply the process of obtaining the state hash *M'* that results from replacing one or more of its input flash drives.
Each replacement is the result of a splicing operation as described above.
The splicing operation is particularly convenient if the flash drive length is a power of 2, and its start is aligned according to its length.
This is why, by default, the `cartesi-machine` command-line utility positions flash drives a multiples of very large powers of 2.

### Result extraction

The most important use for the slicing operation is retrieving computation results.
In a typical scenario, a user posts the final state hash of an instantiated Cartesi Machine that has been run until it halted.
When the other users agree with this final state hash, slicing operations can be used to convince the blockchain of the contents of the halted Cartesi Machine's state.
This can be the value of a single word in a raw output flash drive, or it can be the hash for an entire flash drive.
