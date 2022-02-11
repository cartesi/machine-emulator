#!/bin/python

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

import argparse
import importlib
import logging
import subprocess
import yaml

logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.DEBUG)
logger = logging.getLogger(__name__)

def launch_benchmark(bench_class, bench, emulators):
    for emulator in emulators:
        emu_module = importlib.import_module("emulators.{}".format(emulator))
        emu_obj = emu_module.Emulator(emulators[emulator], "cd /benchmarks && {}".format(bench['command']))
        emu_cmd = emu_obj.build_command()
        emu_env = emu_obj.build_env()

        cmd = "hyperfine -n \"{}: [{}] {}\" \"{}\"".format(emulator,
                bench_class, bench['name'], emu_cmd)
        subprocess.run(cmd, shell=True, env=emu_env)

def parse_benchmark(name, config):
    for benchmark in config['benchmarks']:
        launch_benchmark(name, benchmark, config['emulators'])

def parse_config(config_path):
    with open(config_path, "r") as stream:
        config = yaml.safe_load(stream)
        for bench in config:
            parse_benchmark(bench, config[bench])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Execute cartesi machine benchmarks')
    parser.add_argument('--config', dest='config_path', default='bench.yml',
                        help='benchmarking config path (default: bench.yml)')
    args = parser.parse_args()
    parse_config(args.config_path)
