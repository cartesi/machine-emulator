# gdb script: when the API function API_FN (cm_write_memory or cm_write_word) is entered, finds the shared mapping
# of the RAM backing file RAM_FILE in /proc/<pid>/maps and sets a location watchpoint on byte WATCH_OFF of it.
# When that byte changes (the data store inside machine::write_memory / machine::write_word), the process is
# SIGKILLed, as an OOM kill or crash would stop it at that instruction.
import gdb, os
ram = os.environ["RAM_FILE"]
off = int(os.environ["WATCH_OFF"])
fn = os.environ["API_FN"]
gdb.execute("set pagination off")
gdb.execute("set breakpoint pending on")
gdb.execute("break " + fn)
st = {"phase": 0, "base": None}
def byte():
    return int(gdb.parse_and_eval("*(unsigned char*)%d" % (st["base"] + off)))
def on_stop(ev):
    if st["phase"] == 0 and isinstance(ev, gdb.BreakpointEvent):
        pid = gdb.selected_inferior().pid
        for line in open("/proc/%d/maps" % pid):
            f = line.split()
            if len(f) >= 6 and f[5].endswith("/" + ram) and f[1][3] == "s":
                st["base"] = int(f[0].split("-")[0], 16)
                break
        if st["base"] is None:
            print("HARNESS: shared RAM mapping not found")
            st["phase"] = 3
            return
        print("WATCH-ARMED byte=%d" % byte())
        gdb.execute("delete")
        gdb.execute("watch -l *(unsigned char*)%d" % (st["base"] + off))
        st["phase"] = 1
    elif st["phase"] == 1:
        print("DATA-STORED byte=%d -> SIGKILL" % byte())
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
