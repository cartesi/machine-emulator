#!/usr/bin/env luapp5.3

-- Copyright 2021 Cartesi Pte. Ltd.
--
-- This file is part of the machine-emulator. The machine-emulator is free
-- software: you can redistribute it and/or modify it under the terms of the GNU
-- Lesser General Public License as published by the Free Software Foundation,
-- either version 3 of the License, or (at your option) any later version.
--
-- The machine-emulator is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
-- FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
-- for more details.
--
-- You should have received a copy of the GNU Lesser General Public License
-- along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
--

local cartesi = require "cartesi"

local test_data = {
    zero_keccak_hash_table = {
        "", "",
        "011b4d03dd8c01f1049143cf9c4c817e4b167f1d1b83e5c6f0f10d89ba1e7bce", -- 3
        "4d9470a821fbe90117ec357e30bad9305732fb19ddf54a07dd3e29f440619254", -- 4
        "ae39ce8537aca75e2eff3e38c98011dfe934e700a0967732fc07b430dd656a23", -- 5
        "3fc9a15f5b4869c872f81087bb6104b7d63e6f9ab47f2c43f3535eae7172aa7f", -- 6
        "17d2dd614cddaa4d879276b11e0672c9560033d3e8453a1d045339d34ba601b9", -- 7
        "c37b8b13ca95166fb7af16988a70fcc90f38bf9126fd833da710a47fb37a55e6", -- 8
        "8e7a427fa943d9966b389f4f257173676090c6e95f43e2cb6d65f8758111e309", -- 9
        "30b0b9deb73e155c59740bacf14a6ff04b64bb8e201a506409c3fe381ca4ea90", -- 10
        "cd5deac729d0fdaccc441d09d7325f41586ba13c801b7eccae0f95d8f3933efe", -- 11
        "d8b96e5b7f6f459e9cb6a2f41bf276c7b85c10cd4662c04cbbb365434726c0a0", -- 12
        "c9695393027fb106a8153109ac516288a88b28a93817899460d6310b71cf1e61", -- 13
        "63e8806fa0d4b197a259e8c3ac28864268159d0ac85f8581ca28fa7d2c0c03eb", -- 14
        "91e3eee5ca7a3da2b3053c9770db73599fb149f620e3facef95e947c0ee860b7", -- 15
        "2122e31e4bbd2b7c783d79cc30f60c6238651da7f0726f767d22747264fdb046", -- 16
        "f7549f26cc70ed5e18baeb6c81bb0625cb95bb4019aeecd40774ee87ae29ec51", -- 17
        "7a71f6ee264c5d761379b3d7d617ca83677374b49d10aec50505ac087408ca89", -- 18
        "2b573c267a712a52e1d06421fe276a03efb1889f337201110fdc32a81f8e1524", -- 19
        "99af665835aabfdc6740c7e2c3791a31c3cdc9f5ab962f681b12fc092816a62f", -- 20
        "27d86025599a41233848702f0cfc0437b445682df51147a632a0a083d2d38b5e", -- 21
        "13e466a8935afff58bb533b3ef5d27fba63ee6b0fd9e67ff20af9d50deee3f8b", -- 22
        "f065ec220c1fd4ba57e341261d55997f85d66d32152526736872693d2b437a23", -- 23
        "3e2337b715f6ac9a6a272622fdc2d67fcfe1da3459f8dab4ed7e40a657a54c36", -- 24
        "766c5e8ac9a88b35b05c34747e6507f6b044ab66180dc76ac1a696de03189593", -- 25
        "fedc0d0dbbd855c8ead673544899b0960e4a5a7ca43b4ef90afe607de7698cae", -- 26
        "fdc242788f654b57a4fb32a71b335ef6ff9a4cc118b282b53bdd6d6192b7a82c", -- 27
        "3c5126b9c7e33c8e5a5ac9738b8bd31247fb7402054f97b573e8abb9faad219f", -- 28
        "4fd085aceaa7f542d787ee4196d365f3cc566e7bbcfbfd451230c48d804c017d", -- 29
        "21e2d8fa914e2559bb72bf0ab78c8ab92f00ef0d0d576eccdd486b64138a4172", -- 30
        "674857e543d1d5b639058dd908186597e366ad5f3d9c7ceaff44d04d1550b8d3", -- 31
        "3abc751df07437834ba5acb32328a396994aebb3c40f759c2d6d7a3cb5377e55", -- 32
        "d5d218ef5a296dda8ddc355f3f50c3d0b660a51dfa4d98a6a5a33564556cf83c", -- 33
        "1373a814641d6a1dcef97b883fee61bb84fe60a3409340217e629cc7e4dcc93b", -- 34
        "85d8820921ff5826148b60e6939acd7838e1d7f20562bff8ee4b5ec4a05ad997", -- 35
        "a57b9796fdcb2eda87883c2640b072b140b946bfdf6575cacc066fdae04f6951", -- 36
        "e63624cbd316a677cad529bbe4e97b9144e4bc06c4afd1de55dd3e1175f90423", -- 37
        "847a230d34dfb71ed56f2965a7f6c72e6aa33c24c303fd67745d632656c5ef90", -- 38
        "bec80f4f5d1daa251988826cef375c81c36bf457e09687056f924677cb0bccf9", -- 39
        "8dff81e014ce25f2d132497923e267363963cdf4302c5049d63131dc03fd95f6", -- 40
        "5d8b6aa5934f817252c028c90f56d413b9d5d10d89790707dae2fabb249f6499", -- 41
        "29927c21dd71e3f656826de5451c5da375aadecbd59d5ebf3a31fae65ac1b316", -- 42
        "a1611f1b276b26530f58d7247df459ce1f86db1d734f6f811932f042cee45d0e", -- 43
        "455306d01081bc3384f82c5fb2aacaa19d89cdfa46cc916eac61121475ba2e61", -- 44
        "91b4feecbe1789717021a158ace5d06744b40f551076b67cd63af60007f8c998", -- 45
        "76e1424883a45ec49d497ddaf808a5521ca74a999ab0b3c7aa9c80f85e93977e", -- 46
        "c61ce68b20307a1a81f71ca645b568fcd319ccbb5f651e87b707d37c39e15f94", -- 47
        "5ea69e2f7c7d2ccc85b7e654c07e96f0636ae4044fe0e38590b431795ad0f864", -- 48
        "7bdd613713ada493cc17efd313206380e6a685b8198475bbd021c6e9d94daab2", -- 49
        "214947127506073e44d5408ba166c512a0b86805d07f5a44d3c41706be2bc15e", -- 50
        "712e55805248b92e8677d90f6d284d1d6ffaff2c430657042a0e82624fa3717b", -- 51
        "06cc0a6fd12230ea586dae83019fb9e06034ed2803c98d554b93c9a52348caff", -- 52
        "f75c40174a91f9ae6b8647854a156029f0b88b83316663ce574a4978277bb6bb", -- 53
        "27a31085634b6ec78864b6d8201c7e93903d75815067e378289a3d072ae172da", -- 54
        "fa6a452470f8d645bebfad9779594fc0784bb764a22e3a8181d93db7bf97893c", -- 55
        "414217a618ccb14caa9e92e8c61673afc9583662e812adba1f87a9c68202d60e", -- 56
        "909efab43c42c0cb00695fc7f1ffe67c75ca894c3c51e1e5e731360199e600f6", -- 57
        "ced9a87b2a6a87e70bf251bb5075ab222138288164b2eda727515ea7de12e249", -- 58
        "6d4fe42ea8d1a120c03cf9c50622c2afe4acb0dad98fd62d07ab4e828a94495f", -- 59
        "6d1ab973982c7ccbe6c1fae02788e4422ae22282fa49cbdb04ba54a7a238c6fc", -- 60
        "41187451383460762c06d1c8a72b9cd718866ad4b689e10c9a8c38fe5ef045bd", -- 61
        "785b01e980fc82c7e3532ce81876b778dd9f1ceeba4478e86411fb6fdd790683", -- 62
        "916ca832592485093644e8760cd7b4c01dba1ccc82b661bf13f0e3f34acd6b88" -- 63

    }
}

function test_data.get_cpu_addrx()

    local cpu_addr_x = {}
    cpu_addr_x[0] = 0x000
    cpu_addr_x[1] = 0x008
    cpu_addr_x[2] = 0x010
    cpu_addr_x[3] = 0x018
    cpu_addr_x[4] = 0x020
    cpu_addr_x[5] = 0x028
    cpu_addr_x[6] = 0x030
    cpu_addr_x[7] = 0x038
    cpu_addr_x[8] = 0x040
    cpu_addr_x[9] = 0x048
    cpu_addr_x[10] = 0x050
    cpu_addr_x[11] = 0x058
    cpu_addr_x[12] = 0x060
    cpu_addr_x[13] = 0x068
    cpu_addr_x[14] = 0x070
    cpu_addr_x[15] = 0x078
    cpu_addr_x[16] = 0x080
    cpu_addr_x[17] = 0x088
    cpu_addr_x[18] = 0x090
    cpu_addr_x[19] = 0x098
    cpu_addr_x[20] = 0x0a0
    cpu_addr_x[21] = 0x0a8
    cpu_addr_x[22] = 0x0b0
    cpu_addr_x[23] = 0x0b8
    cpu_addr_x[24] = 0x0c0
    cpu_addr_x[25] = 0x0c8
    cpu_addr_x[26] = 0x0d0
    cpu_addr_x[27] = 0x0d8
    cpu_addr_x[28] = 0x0e0
    cpu_addr_x[29] = 0x0e8
    cpu_addr_x[30] = 0x0f0
    cpu_addr_x[31] = 0x0f8

    return cpu_addr_x
end

function test_data.get_cpu_addr()

    local cpu_addr = {}
    cpu_addr.pc = 0x100
    cpu_addr.mvendorid = -1
    cpu_addr.marchid = -1
    cpu_addr.mimpid = -1
    cpu_addr.mcycle = 0x120
    cpu_addr.minstret = 0x128
    cpu_addr.mstatus = 0x130
    cpu_addr.mtvec = 0x138
    cpu_addr.mscratch = 0x140
    cpu_addr.mepc = 0x148
    cpu_addr.mcause = 0x150
    cpu_addr.mtval = 0x158
    cpu_addr.misa = 0x160
    cpu_addr.mie = 0x168
    cpu_addr.mip = 0x170
    cpu_addr.medeleg = 0x178
    cpu_addr.mideleg = 0x180
    cpu_addr.mcounteren = 0x188
    cpu_addr.stvec = 0x190
    cpu_addr.sscratch = 0x198
    cpu_addr.sepc = 0x1a0
    cpu_addr.scause = 0x1a8
    cpu_addr.stval = 0x1b0
    cpu_addr.satp = 0x1b8
    cpu_addr.scounteren = 0x1c0
    cpu_addr.ilrsc = 0x1c8

    return cpu_addr
end

function test_data.get_cpu_reg_names()

    local cpu_reg_names = {
        "pc", "mvendorid", "marchid", "mimpid", "mcycle", "minstret", "mstatus",
        "mtvec", "mscratch", "mepc", "mcause", "mtval", "misa", "mie", "mip",
        "medeleg", "mideleg", "mcounteren", "stvec", "sscratch", "sepc",
        "scause", "stval", "satp", "scounteren", "ilrsc", "iflags",
        "clint_mtimecmp", "htif_tohost", "htif_fromhost", "htif_ihalt",
        "htif_iconsole", "htif_iyield", "dhd_tstart", "dhd_tlength",
        "dhd_dlength", "dhd_hlength"
    }

    return cpu_reg_names

end




return test_data
