# Copyright 2022 Cartesi Pte. Ltd.
#
# This file is part of the machine-emulator. The machine-emulator is free
# software: you can redistribute it and/or modify it under the terms of the GNU
# Lesser General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# The machine-emulator is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with the machine-emulator. If not, see http://www.gnu.org/licenses/.

import os
import tempfile

class Emulator:
    def __init__(self, config, bench_cmd):
        self.config = config
        self.bench_cmd = bench_cmd

        fd, self.cfg_name = tempfile.mkstemp(text=True)
        with os.fdopen(fd, 'w') as tmp:
            tmp.write("{\nversion: 1,\nmachine: \"riscv64\",\nmemory_size: 512,\n")
            tmp.write("bios: \"{}\",\nkernel:\"{}\",\n".format(self.config['bios'], self.config['kernel']))
            tmp.write("cmdline: \"console=hvc0 rootfstype=ext2 root=/dev/vda rw -- {}\",\n".format(self.bench_cmd))
            tmp.write("drive0: {{ file: \"{}\" }},\n}}".format(self.config['drive']))

    def build_command(self):
        return "temu {}".format(self.cfg_name)

    def build_env(self):
        return {}

    def __del__(self):
        os.remove(self.cfg_name)
