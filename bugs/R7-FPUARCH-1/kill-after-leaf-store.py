# gdb script: at the second cm_get_root_hash call, finds the shared mapping of the RAM .dpt file in /proc/<pid>/maps
# and sets a location watchpoint on the leaf byte of the guest's page. When that byte changes
# (inside dirty_page_tree::do_mark_dirty_leaf_position_and_up), the process is SIGKILLed, as an
# OOM kill or power-cut style crash would stop it at that instruction.
import gdb, os
dpt = os.environ["DPT_FILE"]
leaf = int(os.environ["LEAF_POS"])
gdb.execute("set pagination off")
gdb.execute("set breakpoint pending on")
gdb.execute("break cm_get_root_hash")
gdb.execute("ignore 1 1")
st = {"phase": 0, "base": None}
def byte(off):
    return int(gdb.parse_and_eval("*(unsigned char*)%d" % (st["base"] + off)))
def on_stop(ev):
    if st["phase"] == 0 and isinstance(ev, gdb.BreakpointEvent):
        pid = gdb.selected_inferior().pid
        for line in open("/proc/%d/maps" % pid):
            if line.rstrip().endswith("/" + dpt):
                st["base"] = int(line.split("-")[0], 16)
                break
        if st["base"] is None:
            print("HARNESS: dpt mapping not found")
            st["phase"] = 3
            return
        print("WATCH-ARMED leaf=%d parent=%d" % (byte(leaf), byte(leaf // 2)))
        gdb.execute("delete")
        gdb.execute("watch -l *(unsigned char*)%d" % (st["base"] + leaf))
        st["phase"] = 1
    elif st["phase"] == 1:
        print("LEAF-STORED leaf=%d parent=%d -> SIGKILL" % (byte(leaf), byte(leaf // 2)))
        st["phase"] = 2
gdb.events.stop.connect(on_stop)
gdb.execute("run")
while True:
    try:
        if st["phase"] == 2:
            gdb.execute("signal SIGKILL")
            break
        if st["phase"] == 3:
            gdb.execute("kill")
            break
        gdb.execute("continue")
    except gdb.error as e:
        print("gdb:", e)
        break
