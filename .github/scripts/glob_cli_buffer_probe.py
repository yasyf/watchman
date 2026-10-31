import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import types


class ObservationExpired(Exception):
    pass


def expired(signum, frame):
    raise ObservationExpired("one-second synthetic observation window expired")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    module = source / "watchman/python/pywatchman/__init__.py"
    assert hashlib.sha256(module.read_bytes()).hexdigest() == "e929fad88fde590cc961a70246e6cb45eec50fdb851af18c71c9e15ea95a3b92"
    sys.path.insert(0, str(source / "watchman/python"))
    import pywatchman
    output.mkdir(mode=0o700)
    producer = output / "producer.py"
    producer.write_text("#!" + sys.executable + "\nimport json,os,sys,time\nfrom pathlib import Path\nsys.stdin.buffer.read()\nprint(json.dumps(dict(ok=True)),flush=True)\nPath(os.environ['READY']).touch()\nend=time.monotonic()+10\nwhile not Path(os.environ['RELEASE']).exists() and time.monotonic()<end: time.sleep(0.01)\n")
    producer.chmod(0o700)
    records = []
    previous = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, expired)
    for use_read1 in (False, True):
        prefix = output / ("read1" if use_read1 else "read")
        ready, release = Path(str(prefix) + ".ready"), Path(str(prefix) + ".release")
        os.environ.update(READY=str(ready), RELEASE=str(release))
        transport = pywatchman.CLIProcessTransport(pywatchman.SockPath(unix_domain="private-synthetic-socket"), 80.0, binpath=str(producer))
        codec = pywatchman.JsonCodec(transport)
        value = {"candidate_read1": use_read1, "configured_timeout": transport.timeout, "observation_seconds": 1}
        try:
            codec.send(["private-synthetic-probe"])
            child = transport.proc
            assert isinstance(child.stdout, io.BufferedReader)
            value.update(pid=child.pid, stdout_type=type(child.stdout).__name__, default_buffer_size=io.DEFAULT_BUFFER_SIZE, pipe_blksize=os.fstat(child.stdout.raw.fileno()).st_blksize)
            end = time.monotonic() + 2
            while not ready.exists() and time.monotonic() < end:
                assert child.poll() is None
                time.sleep(0.01)
            assert ready.exists() and select.select([child.stdout], [], [], 0)[0]
            if use_read1:
                def read1(self, size):
                    self._connect()
                    data = self.proc.stdout.read1(size)
                    if not data:
                        raise pywatchman.WatchmanError("EOF on CLI process transport")
                    return data
                transport.readBytes = types.MethodType(read1, transport)
            started = time.monotonic()
            signal.setitimer(signal.ITIMER_REAL, 1)
            try:
                decoded = codec.receive()
                value.update(decoded=decoded, elapsed=time.monotonic() - started, child_still_open=child.poll() is None)
                assert use_read1 and decoded == {"ok": True} and child.poll() is None
            except ObservationExpired:
                value.update(blocked_with_complete_json_ready=True, elapsed=time.monotonic() - started, child_still_open=child.poll() is None)
                assert not use_read1 and child.poll() is None
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
        finally:
            release.touch()
            value["child_exit_after_release"] = transport.proc.wait(timeout=3)
            transport.close()
            records.append(value)
    signal.signal(signal.SIGALRM, previous)
    result = {"status": "PASS_OLD_BUFFERED_READ_BLOCKS_READ1_RETURNS_JSON_WITH_CHILD_STILL_OPEN", "records": records, "scope": "Synthetic complete short JSON held-open producer; one-second observation only, actual Glob cases retain their original80s budget. Test-local read1 candidate only; no product patch or native service."}
    (output / "proof.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
