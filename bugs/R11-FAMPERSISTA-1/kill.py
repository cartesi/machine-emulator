# gdb script: stops the child at cm_run, finds the MAP_SHARED mapping of the stored RAM file in /proc/<pid>/maps,
# sets a hardware watchpoint on the PTE byte in that mapping, and SIGKILLs the child the moment the page walk's
# A-bit store lands in the shared file (i.e. at the first instruction after the store). It prints the backtrace
# and a FRAME line naming the innermost function, so test.lua can check where the store happened.
import gdb, os
ram = os.environ["RAM_FILE"]; off = int(os.environ["WATCH_OFF"]); fn = os.environ["API_FN"]
gdb.execute("set pagination off"); gdb.execute("set breakpoint pending on"); gdb.execute("break " + fn)
st = {"phase": 0, "base": None}
def byte(): return int(gdb.parse_and_eval("*(unsigned char*)%d" % (st["base"] + off)))
def on_stop(ev):
    if st["phase"] == 0 and isinstance(ev, gdb.BreakpointEvent):
        pid = gdb.selected_inferior().pid
        for line in open("/proc/%d/maps" % pid):
            f = line.split()
            if len(f) >= 6 and f[5].endswith("/" + ram) and f[1][3] == "s":
                st["base"] = int(f[0].split("-")[0], 16); break
        if st["base"] is None:
            print("HARNESS: mapping not found"); st["phase"] = 3; return
        print("WATCH-ARMED byte=%d" % byte())
        gdb.execute("delete"); gdb.execute("watch -l *(unsigned char*)%d" % (st["base"] + off)); st["phase"] = 1
    elif st["phase"] == 1:
        print("STORED byte=%d -> SIGKILL" % byte())
        fr = gdb.newest_frame()
        sal = fr.find_sal()
        print("FRAME %s %s:%d" % (fr.name(), sal.symtab.filename if sal.symtab else "?", sal.line))
        gdb.execute("bt 6")
        st["phase"] = 2
gdb.events.stop.connect(on_stop)
gdb.execute("run")
while True:
    try:
        if st["phase"] == 2: gdb.execute("signal SIGKILL"); print("KILLED"); break
        if st["phase"] == 3: gdb.execute("kill"); break
        gdb.execute("continue")
    except gdb.error as e:
        print("gdb:", e); break
