"""Stage 4: cross-mapping admission counters (TC_CROSSMAP_STATS)."""
import json, os, re, subprocess
COMP="/tmp/claude-0/-home-user-machine-emulator/df7f391d-37d7-5139-b76a-fda20c029be9/scratchpad/compete"
CAMP="/tmp/claude-0/-home-user-machine-emulator/df7f391d-37d7-5139-b76a-fda20c029be9/scratchpad/campaign"
IMAGES="/home/user/machine-emulator/tests/build/images"; ROOTFS=os.path.join(COMP,"rootfs-bench.ext2")
RAW="/tmp/claude-0/xmap/results/raw_crossmap"; os.makedirs(RAW, exist_ok=True)
ARGS={"sieve":"--cpu 1 --cpu-method sieve","int64":"--cpu 1 --cpu-method int64","branch":"--branch 1"}
OPSF={"sieve":"--cpu-ops","int64":"--cpu-ops","branch":"--branch-ops"}
ops=json.load(open(os.path.join(COMP,"ops.json")))
recs=[]
for wl in ("sieve","int64","branch"):
    for rep in (1,2,3):
        entry=f"/usr/bin/stress-ng-musl --no-rand-seed {ARGS[wl]} {OPSF[wl]} {ops[wl]}"
        env=dict(os.environ, LUA_CPATH=f"{CAMP}/builds/xmap-instr/?.so;;",
                 TC_CROSSMAP_STATS="1", TC_ONLINE_STATS="1", TC_ONLINE_EXEC_STATS="1")
        r=subprocess.run(["taskset","-c","2","lua5.4",os.path.join(COMP,"compete.lua"),
                          IMAGES,ROOTFS,entry],capture_output=True,text=True,env=env)
        blob=r.stdout+r.stderr
        open(f"{RAW}/sieve_instr.{wl}.r{rep}.log","w").write(blob)
        rec={"workload":wl,"rep":rep}
        last=r.stdout.strip().splitlines()[-1].split()
        rec["mcycle"]=int(last[1])
        for k,p in [("call_probes",r"call-probes (\d+)"),("no_trace",r"no-trace (\d+)"),
                    ("trace_found",r"trace-found (\d+)"),("same",r"\(same (\d+)"),
                    ("cross",r"cross (\d+)\)"),("entry_returned",r"entry-returned (\d+)"),
                    ("entry_rejected",r"entry-rejected (\d+)"),("suppressed",r"suppressed-trip (\d+)"),
                    ("callfn",r"callfn-entries (\d+)"),("accepted",r"accepted (\d+)"),
                    ("tlb_miss",r"tlb-miss (\d+)"),("remap",r"remap (\d+)"),
                    ("ctx_bails",r"ctx-bails (\d+)"),
                    ("inv_probes",r"invariant probes-vs-classes (-?\d+)"),
                    ("inv_callfn",r"callfn-vs-outcomes (-?\d+)"),
                    ("trace_insns",r"trace-insns (\d+)")]:
            m=re.search(p,blob); rec[k]=int(m.group(1)) if m else None
        rec["top"]=re.findall(r"tc-crossmap-top: (.+)",blob)[:20]
        recs.append(rec)
        print(f"{wl} r{rep} probes={rec['call_probes']} cross={rec['cross']} "
              f"callfn={rec['callfn']} accepted={rec['accepted']} "
              f"tlb_miss={rec['tlb_miss']} remap={rec['remap']} inv=({rec['inv_probes']},{rec['inv_callfn']})",
              flush=True)
json.dump(recs,open("/tmp/claude-0/xmap/results/stage4.json","w"),indent=1)
print("STAGE4-DONE",flush=True)
