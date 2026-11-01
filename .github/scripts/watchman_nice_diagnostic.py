import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import uuid
import zipfile


def child_record():
    path = Path(sys.argv[2])
    args = sys.argv[3:]
    path.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "ppid": os.getppid(),
                "pgid": os.getpgrp(),
                "at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "nice": os.getpriority(os.PRIO_PROCESS, 0),
                "argv": args,
                "config": json.loads(Path(os.environ["WATCHMAN_CONFIG_FILE"]).read_text()),
            },
            indent=2,
        )
        + "\n"
    )
    os.execv(args[0], args)


def main():
    os.umask(0o077)
    archive = Path(sys.argv[1])
    output = Path(sys.argv[2])
    output.mkdir(mode=0o700)
    project = Path(__file__).resolve().parents[2]
    owned = []
    result = {
        "status": "DIAGNOSTIC_STARTED_NOT_FULL_SUITE",
        "artifact": 13092856943,
        "historical_inherited_priority": "UNKNOWN",
        "cases": [],
        "static_children": [],
    }

    def tracked_popen(args, **kwargs):
        process = subprocess.Popen(args, **kwargs)
        owned.append((process, list(args)))
        return process

    try:
        assert archive.stat().st_size == 9087633
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == (
            "32ab67dd718e3ba35c000e6bcff6cf91d1bc9571f3cf57da6d6f3b8466e38283"
        )
        payload = output / "payload"
        with zipfile.ZipFile(archive) as data:
            entries = data.infolist()
            assert len(entries) == 23
            assert all(Path(entry.filename).parts[:1] == ("mac",) for entry in entries)
            assert sum(entry.file_size for entry in entries) == 31782344
            data.extractall(payload)
        image = payload / "mac"
        program = image / "bin/watchman"
        assert hashlib.sha256(program.read_bytes()).hexdigest() == (
            "565ee64c435190f9056414b0106ab7a1b727d0725900b54cda35dda77d68685f"
        )
        for entry in entries:
            path = payload / entry.filename
            args = ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(path)]
            check = subprocess.run(args, capture_output=True)
            result["static_children"].append(
                {
                    "argv": args,
                    "returncode": check.returncode,
                    "stderr": check.stderr.decode(errors="replace"),
                }
            )
            assert check.returncode == 0
        program.chmod(0o755)
        os.environ["WATCHMAN_BINARY"] = str(program)
        os.environ["WATCHMAN_NO_SPAWN"] = "1"
        state = output / "state"
        state.mkdir(mode=0o700)
        tempfile.tempdir = str(state)
        source = project / "watchman/integration/lib/WatchmanInstance.py"
        tree = ast.parse(source.read_text())
        names = {"mergeTestConfig", "InitWithFilesMixin", "_Instance", "Instance"}
        selected = [node for node in tree.body if getattr(node, "name", None) in names]
        assert {node.name for node in selected} == names
        namespace = {
            "json": json,
            "os": os,
            "subprocess": SimpleNamespace(Popen=tracked_popen, PIPE=subprocess.PIPE),
            "sys": sys,
            "tempfile": tempfile,
            "uuid": uuid,
        }
        exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), "exec"), namespace)
        nice_source = project / "watchman/integration/test_nice.py"
        prefix_nodes = [
            node
            for node in ast.parse(nice_source.read_text()).body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "NICE_PREFIX" for target in node.targets)
        ]
        assert len(prefix_nodes) == 1
        prefix_namespace = {"sys": sys}
        exec(
            compile(ast.Module(body=prefix_nodes, type_ignores=[]), str(nice_source), "exec"),
            prefix_namespace,
        )
        result["helper_source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        result["test_source_sha256"] = hashlib.sha256(nice_source.read_bytes()).hexdigest()
        result["parent_nice"] = os.getpriority(os.PRIO_PROCESS, 0)
        result["fresh_external_test_config"] = os.getenv("WATCHMAN_TEST_CONFIG")
        for label, prefix, config in [
            ("original_relative_nice", ["nice"], {}),
            ("explicit_positive_nice", list(prefix_namespace["NICE_PREFIX"]), {"min_acceptable_nice_value": 0}),
        ]:
            child_path = output / (label + "-child.json")
            instance = namespace["Instance"](config=config)
            before = len(owned)
            case = {"name": label, "budget_seconds": instance.start_timeout}
            instrumented = prefix + [sys.executable, str(Path(__file__).resolve()), "--record-child", str(child_path)]
            try:
                stdout, stderr = instance.commandViaCLI(["--foreground", "version"], prefix=instrumented)
                case["outcome"] = "exited"
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.output or b"", error.stderr or b""
                case["outcome"] = "existing_budget_exhausted"
            processes = owned[before:]
            assert len(processes) == 1
            process, args = processes[0]
            case.update(
                argv=args,
                returncode=process.poll(),
                helper_reaped_child=process.poll() is not None,
                stdout=stdout.decode(errors="replace"),
                stderr=stderr.decode(errors="replace"),
                child=json.loads(child_path.read_text()) if child_path.exists() else None,
                config=json.loads(Path(instance.cfg_file).read_text()),
                server_log=Path(instance.log_file_name).read_text(errors="replace") if Path(instance.log_file_name).exists() else None,
                shared_server_slot_untouched=instance.proc is None,
            )
            result["cases"].append(case)
            assert case["helper_reaped_child"] and case["shared_server_slot_untouched"]
            assert os.getpriority(os.PRIO_PROCESS, 0) == result["parent_nice"]
            if label == "explicit_positive_nice":
                assert case["child"] is not None and case["child"]["nice"] > 0
                assert case["config"]["min_acceptable_nice_value"] == 0
                assert case["outcome"] == "exited" and case["returncode"] != 0
                assert "refusing to start" in case["stderr"] + (case["server_log"] or "")
        result["status"] = "DIAGNOSTIC_COMPLETE_NOT_FULL_SUITE_OR_LOCAL_ACTIVATION"
    finally:
        for process, args in owned:
            if process.poll() is None:
                process.kill()
            process.wait()
        result["owned_children"] = [
            {"pid": process.pid, "argv": args, "returncode": process.returncode, "still_live": process.poll() is None}
            for process, args in owned
        ]
        result["at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (output / "diagnostic.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--record-child":
        child_record()
    else:
        main()
