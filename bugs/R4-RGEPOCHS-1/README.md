# R4-RGEPOCHS-1: vg.lua referee caps an epoch at 2^16 inputs, the manual's grid is 2^24

## What is asserted

`test.lua` loads `doc/recipes/vg.lua` as a module (`require("vg")`) and checks the verification-game referee:

- control: `new_dapp_contract(hash, inputs)` accepts an epoch of exactly 2^16 inputs (shows setup is sound);
- (A) `new_dapp_contract` accepts an epoch of 2^16 + 1 inputs, a count within the manual's maximum of 2^24;
- (B) the input extent `settle_dispute` bisects over (`log2_input_count`, read from the referee's closure with
  `debug.getupvalue`) equals `cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH` (24). If a fix removes the
  `LOG2_INPUTS_PER_EPOCH` upvalue, (B) is skipped and (A) decides.

Every input path points to one 1-byte file in a `mktemp -d` directory, which the test removes.

## Requirement

doc/README.md, "The state transition function" (the grid the verification game bisects):
"Within the maximum number of inputs per epoch (2^24), attempting to add an input past the last existing input
to a machine will be defined as leaving the machine unchanged." The manual also says of `vg.lua`: "Its referee
stands in for contracts that Cartesi deploys to the blockchain."

THREAT_MODEL.md section 8: "A contradiction between the manual and the behavior on a security-relevant point is
a defect in one of the two. It takes the severity it would have if the manual were right." Section 7 lets the
adversary "Send any number of inputs the deployment accepts".

Defect: `doc/recipes/vg.lua:21` sets `LOG2_INPUTS_PER_EPOCH = 16`; `new_dapp_contract` (`:1030`) asserts
`#input_paths <= INPUTS_PER_EPOCH` ("invalid epoch"), and `settle_dispute` (`:928`) bisects over 2^16 inputs.

## Run

    bugs/run.sh R4-RGEPOCHS-1

Under a second; no machine is run.

## Expected output on audit/prt2

    control: referee accepts an epoch of 65536 inputs
    (A) FAIL: referee refuses an epoch of 65537 inputs (<= 2^24): .../doc/recipes/vg.lua:1030: invalid epoch
    (B) FAIL: referee bisects over 2^16 inputs, manual's grid is 2^24
    VIOLATED: vg.lua referee must settle every epoch within the manual's grid of 2^24 inputs per epoch ...
    run.sh: R4-RGEPOCHS-1: exit 1 (bug present)

Exit 1 while the defect is present; exit 0 once the referee uses the 2^24 grid.
Scope note: the test shows the referee's refusal and its extent, not a wrong hash; the vg player follows
whatever extent the referee sends, so both sides agree on the 2^16 grid. Rating is left to the reviewer.
