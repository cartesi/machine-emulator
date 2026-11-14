#!/usr/bin/env python3
# Run the manual's output verifier (doc/recipes/verify-output-proof.lua) once, under a CPU-time limit (seconds of
# CPU, not wall clock) and an address-space limit, and print one JSON line describing how it ended:
#   {"exit": <status or null>, "signal": <signal or null>, "maxrss_kib": <peak RSS of the child>, "stderr": "..."}
# usage: runcase.py <cpu-seconds> <address-space-KiB> <lua args...>
import json
import os
import resource
import subprocess
import sys


def main():
    cpu = int(sys.argv[1])
    vmem_kib = int(sys.argv[2])
    cmd = sys.argv[3:]

    def limits():
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        resource.setrlimit(resource.RLIMIT_AS, (vmem_kib * 1024, vmem_kib * 1024))

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=limits)
    # the CPU limit bounds the child; this wall-clock bound only protects the harness
    try:
        out, err = p.communicate(timeout=cpu * 20 + 60)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    rc = p.returncode
    print(json.dumps({
        "exit": rc if rc >= 0 else None,
        "signal": -rc if rc < 0 else None,
        "maxrss_kib": ru.ru_maxrss,
        "stdout": out.decode(errors="replace")[-400:],
        "stderr": err.decode(errors="replace")[-400:],
    }))


main()
