## Computation outsourcing case ##

Notation. The machine has:

    [Memory]-[Bootable device]-[In]-[Out]

### Simple Calculations ###

Avg. cost of electricity at households US: 0.125 $/kWh
https://www.eia.gov/electricity/sales_revenue_price/pdf/table4.pdf

Raspberry pi 3 power consumption at 400%: 0.0037 kW
https://www.pidramble.com/wiki/benchmarks/power-consumption

Price of RPi3: 35$

Time necessary for a RPi at 400% load to consume its purchase cost:
75675 h = 8 years



### Posting task ###

Alice posts hash of [Verifier], which is a Bootable device.

### Choosing a bob ###

First Bob to accept makes a deposit and gets the job.

### Given some Bob ###

* Alice: posts encrypted seed
* Bob: posts hash of encrypted solution
* Alice: posts key to seed
* Bob: posts key to solution
* Alice: either pays or challenges

### Challenge ###

* Decrypt Alice's seed (in blockchain)
* Decrypt Bob's solution (in VM with bob's key):

    [M]-[Decryptor]-[Solution]-[Out1]

* Check Bob's solution (in VM with alice's seed):

    [M]-[Verifier]-[Out1]-[Answer]

* If Bob fails, choose a new Bob
