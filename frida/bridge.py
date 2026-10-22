"""Bounded on-demand Frida operations. JSON in/out; diagnostics never enter stdout."""

import json, pathlib, subprocess, sys, threading, time
import frida, frida_tools


def execute(request, on_ready=None):
    snapshot = request["snapshot"]
    pid, tid = int(snapshot["pid"]), int(snapshot["tid"])
    if pid <= 0 or tid <= 0:
        raise ValueError("Invalid PID/TID")
    adb = request.get("adb", "adb")
    serial = request.get("serial", "emulator-5554")
    prefix = [adb, "-s", serial, "shell", "-T", "su", "0"]
    # The installed resolver verifies boot ID and PID start time against the capture.
    validation = {
        "pid": pid,
        "bootId": snapshot["connectionId"].split("/")[0],
        "eventNs": snapshot["capturedAtBootNs"],
        "addresses": [],
    }
    checked = subprocess.run(
        prefix + ["/data/local/tmp/ebpf-analyzer", "symbols"],
        input=json.dumps(validation) + "\n",
        text=True,
        capture_output=True,
        timeout=15,
        check=True,
    )
    answer = json.loads(checked.stdout)
    if "error" in answer:
        raise RuntimeError(answer["error"])
    identity = (
        subprocess.check_output(prefix + ["cat", f"/proc/{pid}/stat"], timeout=5)
        .split(b")")[-1]
        .split()[19]
    )
    device = frida.get_device(serial, timeout=5)
    session = device.attach(pid)
    helper = None
    script = None
    stop = threading.Event()
    captured = threading.Event()
    messages = []
    response = None
    try:
        if (
            subprocess.check_output(prefix + ["cat", f"/proc/{pid}/stat"], timeout=5)
            .split(b")")[-1]
            .split()[19]
            != identity
        ):
            raise RuntimeError("PID changed during attach")
        source = (pathlib.Path(frida_tools.__file__).parent / "bridges" / "java.js").read_text(
            encoding="utf-8"
        )
        source += "\n" + pathlib.Path(__file__).with_name("agent.js").read_text(encoding="utf-8")
        script = session.create_script(source)

        def message(m, data):
            if m.get("type") == "send" and m["payload"].get("type") == "capture":
                messages.append(m["payload"])
                captured.set()
            elif m.get("type") == "error":
                messages.append({"error": m.get("description", "Agent error")})
                captured.set()

        script.on("message", message)
        script.load()
        if request["action"] == "symbols":
            return {"results": script.exports_sync.symbols(request["addresses"])}
        if request["action"] != "capture":
            raise ValueError("Unknown action")
        op = snapshot.get("operation")
        if op not in ("send", "receive"):
            raise ValueError("Select a send or receive event")
        setup = script.exports_sync.prepare(tid)
        script.exports_sync.arm()
        helper = subprocess.Popen(
            prefix
            + [
                "/data/local/tmp/ebpf-analyzer",
                "frida-capture",
                str(pid),
                str(tid),
                op,
                str(snapshot["capturedAtBootNs"]),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        def ping():
            while not stop.is_set():
                try:
                    helper.stdin.write("ping\n")
                    helper.stdin.flush()
                except (OSError, ValueError):
                    return
                stop.wait(0.5)

        heartbeat = threading.Thread(target=ping, daemon=True)
        heartbeat.start()
        ready = json.loads(helper.stdout.readline())
        if not ready.get("ready"):
            raise RuntimeError(ready.get("error", "Capture helper unavailable"))
        if on_ready is not None:
            on_ready()
        line = helper.stdout.readline()
        outcome = json.loads(line)
        helper.wait(timeout=3)
        if "error" in outcome:
            raise RuntimeError(outcome["error"])
        if outcome["SignalResult"] != 0:
            raise RuntimeError("Signal helper returned " + str(outcome["SignalResult"]))
        if not captured.wait(3):
            raise RuntimeError("Signal queued but no Frida capture received")
        event = messages[0]
        if "error" in event:
            raise RuntimeError(event["error"])
        saved = outcome["Saved"]
        registers = event["registers"]
        if (
            event["tid"] != tid
            or int(registers["pc"], 16) != saved[16]
            or int(registers["sp"], 16) != saved[19]
            or int(registers["rax"], 16) != saved[10]
        ):
            raise RuntimeError("Frida context did not match the syscall-exit event")
        event.update(
            {
                "pid": pid,
                "operation": op,
                "phase": "exit",
                "scope": "Next TCP "
                + op
                + " on selected TID; not the historical event or necessarily the same connection",
                "result": outcome["Result"],
                "resultUnit": "messages" if saved[15] in (299, 307) else "bytes",
                "syscall": saved[15],
                "enteredAtBootNs": str(outcome["Entered"]),
                "exitedAtBootNs": str(outcome["Exited"]),
                "skipped": outcome["Skipped"],
                "capturedAtEpochMs": int(time.time() * 1000),
                "setup": setup,
            }
        )
        response = event
        return response
    finally:
        # Stop kernel production first, then disarm the exception handler and detach.
        stop.set()
        if helper is not None:
            try:
                helper.stdin.close()
            except (OSError, ValueError):
                pass
            try:
                helper.wait(timeout=4)
            except subprocess.TimeoutExpired:
                helper.kill()
                helper.wait()
        if script is not None:
            try:
                script.exports_sync.stop()
            except frida.InvalidOperationError:
                pass
        # Frida may defer unload while an already-entered native call is blocked.
        # Capture is already disarmed; do not hold the UI waiting for cleanup.
        cancellation = frida.Cancellable()
        timer = threading.Timer(2, cancellation.cancel)
        timer.start()
        try:
            with cancellation:
                session.detach()
            if response is not None:
                response["cleanup"] = "Detached"
        except frida.OperationCancelledError:
            if response is not None:
                response["cleanup"] = "Capture disarmed; agent unload deferred"
        except frida.InvalidOperationError:
            pass
        finally:
            timer.cancel()


if __name__ == "__main__":
    try:
        raw = sys.stdin.buffer.readline(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("Request exceeds limit")
        print(json.dumps(execute(json.loads(raw))))
    except Exception as error:
        print(json.dumps({"error": str(error)}))
        sys.exit(1)
