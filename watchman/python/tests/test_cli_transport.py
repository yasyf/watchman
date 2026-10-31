import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import pywatchman


class TestCLIProcessTransport(unittest.TestCase):
    def test_receive_complete_frames_before_child_exits(self):
        producer = """import json
from pathlib import Path
import sys
import time

sys.stdin.buffer.read()
print(json.dumps({"ok": True}), flush=True)
print(json.dumps({"second": True}), flush=True)
release = Path(sys.argv[1])
deadline = time.monotonic() + 5
while not release.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
"""
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release"
            process = subprocess.Popen(
                [sys.executable, "-c", producer, str(release)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            transport = pywatchman.CLIProcessTransport(
                pywatchman.SockPath(unix_domain="private-test-socket"),
                80.0,
                binpath="private-test-cli",
            )
            codec = pywatchman.JsonCodec(transport)
            try:
                with patch("pywatchman.subprocess.Popen", return_value=process) as start:
                    codec.send(["version"])
                    self.assertIsInstance(process.stdout, io.BufferedReader)
                    self.assertTrue(process.stdin.closed)
                    self.assertEqual(codec.receive(), {"ok": True})
                    self.assertEqual(codec.receive(), {"second": True})
                    self.assertIsNone(
                        process.poll(), "CLI exited before the frames were decoded"
                    )
                    self.assertIs(transport.proc, process)
                    start.assert_called_once()
            finally:
                release.touch()
                process.wait(timeout=10)
                transport.close()
