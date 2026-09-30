# GVAP-Fuzz runtime monitor (VTest platform).
# Shared memory gvap_vtest_shm and pipe \\.\pipe\gvap_vtest_pipe are provided by the
# VTest simulation platform. F run, K finished, E exception, G = uint16 LE + JSON,
# I inject = b"I" + uint16 LE + {"irq": name}. An unseen GVAP is an interesting input.

import argparse
import atexit
import enum
import glob
import hashlib
import json
import mmap
import os
import struct
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.abspath(os.path.join(_HERE, "..", ".."))
sys.path.insert(0, os.path.join(_SRC, "input_generator", "vtest"))
sys.path.insert(0, os.path.join(_SRC, "interrupt_controller", "vtest"))
sys.path.insert(0, _HERE)
import mutater
import gvap_monitor
import gvap_injection

try:
    import pywintypes
    import win32api
    import win32event
    import win32file
    import win32pipe
    import winerror
except ImportError:
    pywintypes = win32api = win32event = win32file = win32pipe = winerror = None

MAP_SIZE = 1 << 16
CURINPUTNAME = "cur_input"
OUTPUTDIRNAME = "fuzzeroutput"
ENTRYFILENAME = "testcase_entry.json"
SHM_NAME = "gvap_vtest_shm"
PIPE_NAME = r"\\.\pipe\gvap_vtest_pipe"
CMD_SERVER = "VTest.CmdServer.exe"

inputDir = outputDir = DTPDir = projectDir = versionName = ""
sourcecodePath = binfilePath = testcaseDir = ""
execTimeout = 12000 * 1000
childObj = pipeHandle = pipeOverlapped = shmObj = None
traceBits = None
virginBits = bytearray(b"\xff" * MAP_SIZE)
virginTimeout = bytearray(b"\xff" * MAP_SIZE)
virginCrash = bytearray(b"\xff" * MAP_SIZE)
queuedPaths = 0
cur_pool = 3
queue = []
retExceptionList = []
_inject_base = {"n": None}


class Fault(enum.Enum):
    FAULT_NONE = enum.auto()
    FAULT_TMOUT = enum.auto()
    FAULT_CRASH = enum.auto()


class QueueEntry:
    def __init__(self, fname, subname):
        self.fname, self.subname = fname, subname
        self.wasFuzzed = False
        self.min_dist = 10 ** 9


def parseArgs():
    """Interface shape: -i -D -P -S -B -p --inject."""
    global inputDir, DTPDir, projectDir, versionName, sourcecodePath, binfilePath, cur_pool
    parser = argparse.ArgumentParser(description="GVAP-Fuzz fuzzing driver for the VTest simulation platform")
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-D", "--DTP", required=True)
    parser.add_argument("-P", "--Project", required=True)
    parser.add_argument("-S", "--sourcecode", required=True)
    parser.add_argument("-B", "--binfile", required=True)
    parser.add_argument("-p", "--pool", type=int)
    parser.add_argument("--inject", action="store_true", help="phase 2: GVAP-aware interrupt injection, corresponding to validate")
    args = parser.parse_args()
    inputDir, DTPDir, projectDir = map(os.path.normpath, (args.input, args.DTP, args.Project))
    sourcecodePath, binfilePath = map(os.path.normpath, (args.sourcecode, args.binfile))
    cur_pool = args.pool or 3
    versionName = os.path.basename(inputDir)


def setupShm():
    """Bitmap layout is provided by the VTest simulation platform."""
    global shmObj
    shmObj = mmap.mmap(-1, MAP_SIZE, SHM_NAME)
    atexit.register(shmObj.close)


def writeShm(buf):
    shmObj.seek(0)
    shmObj.write(bytes(buf))


def readShm():
    shmObj.seek(0)
    return bytearray(shmObj.read(MAP_SIZE))


def setupDirs():
    global outputDir, testcaseDir
    testcaseDir = os.path.join(inputDir, "testcases")
    outputDir = os.path.join(testcaseDir, OUTPUTDIRNAME)
    for name in (outputDir, os.path.join(outputDir, "queue1"), os.path.join(outputDir, "queue2"),
                 os.path.join(outputDir, "queue3"), os.path.join(outputDir, "crashes"),
                 os.path.join(outputDir, "timeouts")):
        os.makedirs(name, exist_ok=True)


def dump_json(path, obj):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle)
        handle.write("\n")


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def pipe_read(n, timeout):
    if not pipeHandle or n <= 0:
        return b""
    buf = win32file.AllocateReadBuffer(n)
    hr, buf = win32file.ReadFile(pipeHandle, buf, pipeOverlapped)
    if hr in (0, winerror.ERROR_IO_PENDING):
        if win32event.WaitForSingleObject(pipeOverlapped.hEvent, timeout) != win32event.WAIT_OBJECT_0:
            return b""
        if win32file.GetOverlappedResult(pipeHandle, pipeOverlapped, False) != n:
            return b""
        return bytes(buf[:n])
    return b""


def pipe_write(data):
    if pipeHandle:
        win32file.WriteFile(pipeHandle, data if isinstance(data, bytes) else data.encode(), pipeOverlapped)


def read_access(timeout):
    hdr = pipe_read(2, timeout)
    if len(hdr) != 2:
        return None
    n = struct.unpack("<H", hdr)[0]
    body = pipe_read(n, timeout)
    return json.loads(body.decode("utf-8")) if len(body) == n else None


def isChildRunning():
    return childObj is not None and childObj.poll() is None


def createTargetProcess():
    global childObj, pipeHandle, pipeOverlapped
    pipeOverlapped = pywintypes.OVERLAPPED()
    pipeOverlapped.hEvent = win32event.CreateEvent(None, True, True, None)
    pipeHandle = win32pipe.CreateNamedPipe(
        PIPE_NAME, win32pipe.PIPE_ACCESS_DUPLEX | win32file.FILE_FLAG_OVERLAPPED,
        0, 1, 512, 512, 20000, None)
    argv = [os.path.join(DTPDir, CMD_SERVER), "ETC", "-root", projectDir, "-json",
            os.path.join(inputDir, ENTRYFILENAME), "-r", os.path.join(projectDir, "cmdResult"),
            "-s", "true", "-w", "false"]
    childObj = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    win32pipe.ConnectNamedPipe(pipeHandle, pipeOverlapped)


def destroyTargetProcess():
    global childObj, pipeHandle
    if childObj is not None:
        subprocess.Popen(["taskkill", "/F", "/T", "/PID", str(childObj.pid)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        childObj = None
    if pipeHandle is not None and win32pipe:
        win32pipe.DisconnectNamedPipe(pipeHandle)
        win32api.CloseHandle(pipeHandle)
        pipeHandle = None


def collectAccesses(budget, stop):
    found = []
    while isChildRunning() and budget > 0:
        cmd = pipe_read(1, budget).decode(errors="replace")
        if cmd == "G":
            ev = read_access(budget)
            if ev is None:
                break
            found.append(ev)
            if stop(ev):
                break
        elif cmd in ("K", ""):
            break
        budget -= 1
    return found


def add_to_queue(fname, subname):
    global queuedPaths
    queue.append(QueueEntry(fname, subname))
    queuedPaths += 1


def hasNewBits(virginMap):
    """Coverage bucket is one expression. Unseen GVAP forces the input to count as new."""
    if virginMap is virginBits:
        gvap_monitor.MONITOR.paint(traceBits)
    ret = 0
    for i in range(MAP_SIZE):
        if traceBits[i]:
            traceBits[i] = 1 << min(7, traceBits[i].bit_length() - 1)
        if traceBits[i] and (traceBits[i] & virginMap[i]):
            ret = 2 if virginMap[i] == 0xFF else max(ret, 1)
            virginMap[i] &= ~traceBits[i]
    if virginMap is virginBits and gvap_monitor.MONITOR.has_unseen() and ret == 0:
        ret = 2
    return ret


def saveIfInteresting(tc, subname, fault):
    if fault != Fault.FAULT_NONE or not hasNewBits(virginBits):
        return False
    fn = os.path.join(outputDir, "queue%d" % cur_pool, "id_%06d.json" % queuedPaths)
    q = QueueEntry(fn, subname)
    q.min_dist = gvap_monitor.MONITOR.shortest_new()
    queue.append(q)
    gvap_monitor.MONITOR.commit_interesting(fn, subname)
    gvap_monitor.MONITOR.save(outputDir)
    dump_json(fn, tc)
    return True


def runDTP(timeout):
    global traceBits, retExceptionList
    gvap_monitor.MONITOR.reset_execution()
    writeShm(bytearray(MAP_SIZE))
    retExceptionList = []
    if not isChildRunning():
        createTargetProcess()
    pipe_write("F")
    fault = Fault.FAULT_NONE
    for ev in collectAccesses(timeout, lambda ev: False):
        gvap_monitor.MONITOR.on_access(ev)
    traceBits = readShm()
    gvap_monitor.MONITOR.paint(traceBits)
    gvap_monitor.MONITOR.save(outputDir)
    if isChildRunning():
        destroyTargetProcess()
    return fault


def commonFuzzStuff(tc, subname):
    dump_json(os.path.join(inputDir, ENTRYFILENAME), tc)
    fault = runDTP(execTimeout)
    saveIfInteresting(tc, subname, fault)
    return fault


def fuzz_one(q):
    tc = load_json(q.fname)
    print("Begin fuzz:", q.fname)
    if cur_pool == 1:
        for _ in range(10):
            mutated, subname = mutater.change_cmd_id_and_CANType(tc)
            commonFuzzStuff(mutated, subname)
    else:
        commonFuzzStuff(tc, q.subname)
    q.wasFuzzed = True


def generate_testcase_pool2(input_dir, testcase_set_path):
    tc = load_json(testcase_set_path)
    items = tc["TestCases"][0]["Items"]
    if len(items) <= 6:
        return
    rel = items[6]["Arguments"][2]
    path = os.path.join(input_dir, rel)
    for fn in (mutater.mutate_bitflip, mutater.mutate_arithmetic, mutater.mutate_interest, mutater.random_havoc):
        fn(path)
    directory, filename = os.path.split(path)
    mutated = [name for name in os.listdir(directory) if name.startswith(filename[:-4] + "_mutated_")]
    frames = [item for item in items if "frame)" in item.get("Name", "")]
    rel_dir = os.path.dirname(rel)
    for num, name in enumerate(mutated):
        if not frames:
            break
        frames[num % len(frames)]["Arguments"][2] = os.path.join(rel_dir, name)
        fname = testcase_set_path[:-5] + "_mutated_%d.json" % num
        dump_json(fname, tc)
        add_to_queue(fname, tc["TestCases"][0]["Code"])


def generate_testcase_pool3(testcase_set_path):
    tc = load_json(testcase_set_path)
    name = os.path.basename(testcase_set_path)
    made = []
    made += mutater.changetime(tc, name, outputDir)
    made += mutater.discordcommand(tc, name, outputDir)
    made += mutater.swapsequence(tc, name, outputDir)
    made += mutater.insert_packet(tc, name, outputDir)
    for filename in made:
        add_to_queue(filename, tc["TestCases"][0]["Code"])


def readTestcases():
    for path in sorted(glob.glob(os.path.join(testcaseDir, "**", "*.json"), recursive=True)):
        if os.path.relpath(path, testcaseDir).startswith(OUTPUTDIRNAME + os.sep):
            continue
        if cur_pool == 2:
            generate_testcase_pool2(inputDir, path)
        elif cur_pool == 3:
            generate_testcase_pool3(path)
        else:
            add_to_queue(path, load_json(path)["TestCases"][0]["Code"])


def pick_seed(cursor):
    idx = gvap_monitor.Monitor.pick_index([(q.wasFuzzed, q.min_dist) for q in queue], cursor)
    return queue[idx]


def replay_until(row):
    """True only after GVAx is seen again under the same execution context."""
    tc = load_json(row["input"])
    dump_json(os.path.join(inputDir, ENTRYFILENAME), tc)
    if not isChildRunning():
        createTargetProcess()
    pipe_write("F")
    ctx, x = row.get("exec_ctx") or {}, (row.get("gvap") or {}).get("x") or {}

    def stop(ev):
        return gvap_injection.same_gva(ev, x) and gvap_injection.same_context(ev, ctx)

    for ev in collectAccesses(execTimeout, stop):
        if stop(ev):
            _inject_base["n"] = ev.get("icount")
            return True
    return False


def trigger(irq):
    payload = json.dumps({"irq": irq}).encode("utf-8")
    pipe_write(b"I" + struct.pack("<H", len(payload)) + payload)


def collect_handler_accesses():
    evs = collectAccesses(execTimeout, lambda ev: bool(ev.get("irq_boundary")))
    return [ev for ev in evs if ev.get("exec_ctx") == "handler"]


def resume_and_watch(limit):
    start = _inject_base["n"]

    def stop(ev):
        return int(ev.get("icount") or 0) - int(start or 0) >= limit

    return collectAccesses(execTimeout, stop)


def inject_main():
    """Phase 2. An empty GVAP table returns before the simulator is started."""
    parseArgs()
    setupDirs()
    table = gvap_injection.load_json(os.path.join(outputDir, "gvap_table.json"), [])
    if not table:
        print("GVAP table is empty")
        return
    patterns = gvap_injection.load_json(os.path.join(outputDir, "gvap_patterns.json"), [])
    enabled = gvap_injection.load_enabled(os.path.join(outputDir, "enabled_interrupts.json"))
    setupShm()
    gvap_injection.inject_all(table, enabled, patterns, outputDir,
                              replay_until, trigger, collect_handler_accesses, resume_and_watch)
    if isChildRunning():
        destroyTargetProcess()


def fuzzMain():
    parseArgs()
    setupShm()
    setupDirs()
    readTestcases()
    cursor = 0
    while queue:
        q = pick_seed(cursor)
        fuzz_one(q)
        cursor += 1


if __name__ == "__main__":
    if "--inject" in sys.argv:
        inject_main()
    else:
        fuzzMain()
