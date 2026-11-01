import argparse
import atexit
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback
import types

SOURCE = "60f821ae5c3bf5578025f3699b888e76a7738fcd"
CASES = (
    "watchman.integration.test_glob.TestGlobCliJson.test_glob",
    "watchman.integration.test_glob.TestGlobCliJson.test_glob_generator_absolute",
)
SOURCE_FILES = {
    "watchman/integration/test_glob.py": "e67b8c9fda7181a57aed25b75b15a9fa975e379e46f3d3f54773533350f1aaa9",
    "watchman/integration/lib/WatchmanTestCase.py": "58e9174744f115bf8d7fef2b528cc82509849ceedc5815e34b40d5dcf6c1c7a5",
    "watchman/integration/lib/WatchmanInstance.py": "8046403a2159de5fbbb11be984d698db7e8ebba3adcae62348c04b465acbb6e5",
    "watchman/integration/lib/TempDir.py": "f44db8c87bb9e6e441111edb1988a75da95311b6115dc66776dd7af84b283c56",
    "watchman/python/pywatchman/__init__.py": "e929fad88fde590cc961a70246e6cb45eec50fdb851af18c71c9e15ea95a3b92",
    "build/fbcode_builder/CMake/fb_py_test_main.py": "a239f14387664b590bc290cc6f38da1ea2fdcdf7eb54669dcedf45002f6c4255",
}


def run_case(args):
    source, binary, output = args.source.resolve(), args.binary.resolve(), args.output.resolve()
    for name, digest in SOURCE_FILES.items():
        assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest
    sys.path[:0] = [str(source / "watchman/python"), str(source)]
    os.environ.update(WATCHMAN_BINARY=str(binary), WATCHMAN_SRC_DIR=str(source / "watchman"), WATCHMAN_NO_SPAWN="1", WATCHMAN_TEST_KEEP="1", HGUSER="John Smith <smith@example.com>", NOSCMLOG="1", WATCHMAN_EMPTY_ENV_VAR="")
    cli, servers, collectors = {}, {}, []
    trace_bytes = 0

    def emit(event, **values):
        nonlocal trace_bytes
        data = (json.dumps({"at_monotonic": time.monotonic(), "event": event, **values}) + "\n").encode()
        trace_bytes += len(data)
        assert trace_bytes <= 2 * 1024 * 1024
        with (output / "trace.jsonl").open("ab", buffering=0) as stream:
            assert stream.write(data) == len(data)

    def final_state():
        values = {"source": SOURCE, "case": CASES[args.case], "python": sys.version, "case_pid": os.getpid(), "cli": [{"pid": p.pid, "argv": p.args, "exit": p.poll(), "stdout_bytes": v["total"]} for p, v in cli.items()], "servers": [{"pid": p.pid, "argv": p.args, "exit": p.poll()} for p in servers.values()], "collectors": [{"pid": p.pid, "argv": p.args, "exit": p.poll()} for p in collectors], "external_signals_added": 0, "timeout_seconds": 80, "scope": "Original source test and CLI flags; diagnostic raw-read observation and own-Python timeout only. Upstream private-child cleanup is unchanged."}
        (output / "final.json").write_text(json.dumps(values, indent=2) + "\n")

    atexit.register(final_state)
    import pywatchman
    from watchman.integration.lib import WatchmanInstance

    original_connect = pywatchman.CLIProcessTransport._connect
    original_read = pywatchman.CLIProcessTransport.readBytes
    original_write = pywatchman.CLIProcessTransport.write
    original_instance = WatchmanInstance.getSharedInstance

    def connect(self):
        process = original_connect(self)
        if process not in cli:
            assert process.args[0] == str(binary)
            assert process.args[3:] == ["--logfile=/BOGUS", "--statefile=/BOGUS", "--no-spawn", "--no-local", "--no-pretty", "-j"]
            stream = process.stdout
            assert isinstance(stream, io.BufferedReader) and isinstance(stream.raw, io.FileIO)
            raw_read = stream.raw.readinto
            state = {"partial": bytearray(), "total": 0}

            def observe_raw(target):
                emit("RAW_READ_BEGIN", pid=process.pid, requested=len(target))
                count = raw_read(target)
                assert count is not None
                data = bytes(target[:count])
                state["partial"].extend(data[:max(0, 16384 - len(state["partial"]))])
                state["total"] += count
                emit("RAW_READ_RETURN", pid=process.pid, count=count, prefix_hex=data[:256].hex(), truncated=count > 256, sha256=hashlib.sha256(data).hexdigest())
                return count

            stream.raw.readinto = observe_raw
            assert process.stdout is stream
            cli[process] = state
            emit("CLI_CREATED", pid=process.pid, parent=os.getpid(), argv=process.args, stdout_type=type(stream).__name__, raw_type=type(stream.raw).__name__, default_buffer_size=io.DEFAULT_BUFFER_SIZE, pipe_blksize=os.fstat(stream.raw.fileno()).st_blksize)
        return process

    def instance(config=None):
        value = original_instance(config)
        servers[value.getUnixSockPath()] = value.proc
        emit("PRIVATE_SERVER", pid=value.proc.pid, argv=value.proc.args, socket=value.getUnixSockPath())
        return value

    def capture_tool(argv, stem):
        with (output / (stem + ".stdout")).open("xb") as stdout, (output / (stem + ".stderr")).open("xb") as stderr:
            child = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True)
            collectors.append(child)
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                emit("COLLECTOR_PENDING_NO_SIGNAL", pid=child.pid, argv=argv)

    def write(self, data):
        emit("CLI_WRITE_BEGIN", bytes=len(data), prefix_hex=data[:4096].hex(), truncated=len(data) > 4096, sha256=hashlib.sha256(data).hexdigest())
        value = original_write(self, data)
        emit("CLI_WRITE_RETURN", pid=self.proc.pid, bytes=value)
        return value

    def read(self, size):
        process = self._connect()
        assert self.timeout == 80.0 and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
        started = time.monotonic()
        previous = signal.getsignal(signal.SIGALRM)

        def expired(signum, frame):
            traced = cli[process]
            stem = "timeout-" + str(process.pid) + "-" + str(time.monotonic_ns())
            (output / (stem + ".partial.stdout")).write_bytes(traced["partial"])
            values = {"pid": process.pid, "argv": process.args, "exit": process.poll(), "elapsed": time.monotonic() - started, "stdout_bytes": traced["total"], "partial_bytes": len(traced["partial"]), "partial_truncated": traced["total"] > len(traced["partial"]), "python_stack": traceback.format_stack(frame)}
            (output / (stem + ".json")).write_text(json.dumps(values, indent=2) + "\n")
            emit("CLI_READ_TIMEOUT", **{k: v for k, v in values.items() if k != "python_stack"})
            for role, child in [("cli", process), ("server", servers[self.sockpath.unix_domain])]:
                if child.poll() is None:
                    capture_tool(["/bin/ps", "-ww", "-p", str(child.pid), "-o", "pid=,ppid=,pgid=,uid=,tty=,lstart=,command="], stem + "-" + role + "-identity")
                    capture_tool(["/usr/bin/sample", str(child.pid), "1", "1", "-file", str(output / (stem + "-" + role + ".sample"))], stem + "-" + role + "-sample")
            raise pywatchman.SocketTimeout("CLI transport exceeded its configured 80-second read budget")

        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, self.timeout)
        emit("CLI_BUFFERED_READ_BEGIN", pid=process.pid, requested=size, timeout=self.timeout)
        try:
            value = original_read(self, size)
            emit("CLI_BUFFERED_READ_RETURN", pid=process.pid, count=len(value), elapsed=time.monotonic() - started, exit=process.poll())
            return value
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)

    pywatchman.CLIProcessTransport._connect = connect
    pywatchman.CLIProcessTransport.readBytes = read
    pywatchman.CLIProcessTransport.write = write
    WatchmanInstance.getSharedInstance = instance
    modules = types.ModuleType("__test_modules__")
    modules.TEST_MODULES = ["watchman.integration.test_glob"]
    sys.modules[modules.__name__] = modules
    path = source / "build/fbcode_builder/CMake/fb_py_test_main.py"
    spec = importlib.util.spec_from_file_location("source_fb_test_main", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    emit("SOURCE_RUNNER", case=CASES[args.case], source=SOURCE, binary=str(binary), codec=pywatchman.bser.__name__)
    return runner.MainProgram([str(path), CASES[args.case]]).run()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--case", type=int, choices=(0, 1))
    args = parser.parse_args()
    if args.case is not None:
        return run_case(args)
    args.output.mkdir(mode=0o700)
    workers = []
    for number in range(2):
        output = args.output / str(number)
        output.mkdir()
        temporary = output / "tmp"
        temporary.mkdir()
        env = dict(os.environ, TMPDIR=str(temporary.resolve()), PYTHONDONTWRITEBYTECODE="1")
        stdout = (output / "case.stdout").open("xb")
        stderr = (output / "case.stderr").open("xb")
        argv = [sys.executable, str(Path(__file__).resolve()), str(args.source.resolve()), str(args.binary.resolve()), str(output.resolve()), "--case", str(number)]
        process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, env=env, start_new_session=True)
        workers.append((process, stdout, stderr, output))
    codes = []
    for process, stdout, stderr, output in workers:
        codes.append(process.wait())
        stdout.close()
        stderr.close()
    results = []
    for (process, stdout, stderr, output), code in zip(workers, codes):
        final = json.loads((output / "final.json").read_text())
        ended = all(p["exit"] is not None for group in ("cli", "servers", "collectors") for p in final[group])
        results.append({"case": final["case"], "worker_pid": process.pid, "exit": code, "owned_children_ended": ended, "timeouts": len(list(output.glob("timeout-*.json")))})
    summary = {"source": SOURCE, "results": results, "scope": "Only the two exact GlobCliJson methods against fixed artifactB; not the full622 suite", "no_builds": True, "no_host_service": True}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if all(r["exit"] == 0 and r["owned_children_ended"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
