"""PID-wide capture, JSON lines until stdin closes. No libc hooks."""

import base64, json, pathlib, queue, subprocess, sys, threading, time
import frida, frida_tools


def run(request, emit, on_ready=None, commands=None):
    snapshot = request["snapshot"]
    pid = int(snapshot["pid"])
    if pid <= 0:
        raise ValueError("Invalid PID")
    prefix = [
        request.get("adb", "adb"),
        "-s",
        request.get("serial", "emulator-5554"),
        "shell",
        "-T",
        "su",
        "0",
    ]
    validation = {
        "pid": pid,
        "bootId": snapshot["connectionId"].split("/")[0],
        "eventNs": snapshot["capturedAtBootNs"],
        "addresses": [],
    }
    answer = json.loads(
        subprocess.check_output(
            prefix + ["/data/local/tmp/ebpf-analyzer", "symbols"],
            input=(json.dumps(validation) + "\n").encode(),
            timeout=15,
        )
    )
    if "error" in answer:
        raise RuntimeError(answer["error"])

    def identity():
        return (
            subprocess.check_output(prefix + ["cat", f"/proc/{pid}/stat"], timeout=5)
            .rsplit(b")", 1)[1]
            .split()[19]
        )

    original = identity()
    session = frida.get_device(request.get("serial", "emulator-5554"), timeout=5).attach(pid)
    script = None
    helper = None
    stop = threading.Event()
    inbox = queue.Queue(maxsize=4096)
    inspections = queue.Queue(maxsize=16)
    lock = threading.Lock()

    def put(item):
        while not stop.is_set():
            try:
                inbox.put(item, timeout=0.2)
                return
            except queue.Full:
                pass

    def write(line):
        with lock:
            helper.stdin.write(line + "\n")
            helper.stdin.flush()

    try:
        if identity() != original:
            raise RuntimeError("PID changed during attach")
        source = (
            (pathlib.Path(frida_tools.__file__).parent / "bridges/java.js").read_text(
                encoding="utf-8"
            )
            + "\n"
            + pathlib.Path(__file__).with_name("agent.js").read_text(encoding="utf-8")
        )
        script = session.create_script(source)
        script.on("message", lambda m, d: put(("agent", m, d)))
        script.load()
        script.exports_sync.prepare(0, True)
        script.exports_sync.arm()
        helper = subprocess.Popen(
            prefix + ["/data/local/tmp/ebpf-analyzer", "frida-stream", str(pid)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        def heartbeat():
            while not stop.is_set():
                try:
                    write("ping")
                except (OSError, ValueError):
                    return
                stop.wait(0.5)

        def reader():
            for line in helper.stdout:
                try:
                    put(("kernel", json.loads(line), None))
                except ValueError:
                    put(("error", "Invalid helper response", None))
            put(("error", "Capture helper stopped", None))

        def control():
            for line in commands or sys.stdin:
                if line.strip() == "stop":
                    break
                try:
                    command = json.loads(line)
                    if command.get("action") in ("catalog", "members"):
                        inspections.put_nowait(command)
                except (ValueError, AttributeError, queue.Full):
                    put(("inspection", {"type": "catalogError", "error": "Invalid request or inspection queue is full"}, None))
            put(("stop", None, None))

        def inspect():
            while not stop.is_set():
                try:
                    command = inspections.get(timeout=0.25)
                except queue.Empty:
                    continue
                cancellation = frida.Cancellable()
                timer = threading.Timer(15, cancellation.cancel)
                timer.start()
                try:
                    with cancellation:
                        if command["action"] == "catalog":
                            result = script.exports_sync.catalog()
                            result["type"] = "catalog"
                        else:
                            result = script.exports_sync.members(command.get("kind", ""), command.get("name", ""))
                            result["type"] = "members"
                    put(("inspection", result, None))
                except Exception as error:
                    put(("inspection", {"type": "catalogError", "kind": command.get("kind", ""),
                        "name": command.get("name", ""), "error": str(error)}, None))
                finally:
                    timer.cancel()

        for fn in (heartbeat, reader, control, inspect):
            threading.Thread(target=fn, daemon=True).start()
        pending = {}
        captures = {}
        names = [
            "r15",
            "r14",
            "r13",
            "r12",
            "rbp",
            "rbx",
            "r11",
            "r10",
            "r9",
            "r8",
            "rax_saved",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "orig_rax",
            "rip",
            "cs",
            "rflags",
            "rsp",
            "ss",
        ]

        def output(k, capture=None, data=None, reason="Captured"):
            saved = k["Saved"]
            stamp = str(k["Exited"])
            event = dict(capture or {})
            regs = {n: hex(v) for n, v in zip(names, saved)}
            event.update(
                type="event",
                pid=pid,
                tid=k["TID"],
                operation="send" if k["Operation"] == 1 else "receive",
                phase="exit",
                eventId=validation["bootId"] + "/frida/" + str(k["TID"]) + "/" + stamp,
                connectionId=validation["bootId"] + "/frida/" + stamp,
                capturedAtBootNs=stamp,
                capturedAtEpochMs=k.get("AtEpochMs", int(time.time() * 1000)),
                syscallPc=hex(saved[16] - 2),
                registers=regs,
                stack=base64.b64encode(data or b"").decode(),
                stackBase=hex(saved[19]),
                requestedIoBytes=str(k["Requested"]),
                result=k["Result"],
                resultUnit="messages" if saved[15] in (299, 307) else "bytes",
                status=reason,
                scope="All TCP I/O in selected PID",
            )
            event.setdefault("nativeFrames", [])
            event.setdefault("java", {"frames": [], "error": reason, "source": "Exception handler"})
            emit(event)

        while True:
            try:
                kind, value, data = inbox.get(timeout=0.25)
            except queue.Empty:
                kind = None
            if kind == "stop":
                break
            if kind == "error":
                raise RuntimeError(value)
            if kind == "inspection":
                emit(value)
            if kind == "kernel":
                if value.get("type") == "error":
                    raise RuntimeError(value["error"])
                if value.get("type") == "ready":
                    emit(value)
                    try:
                        inspections.put_nowait({"action": "catalog"})
                    except queue.Full:
                        pass
                    if on_ready:
                        on_ready()
                elif value.get("type") == "stats":
                    emit(value)
                elif "TID" in value:
                    if value["Flags"] == 1:
                        pending[value["TID"]] = [value, time.monotonic(), False]
                    else:
                        output(
                            value,
                            reason={
                                2: "Stack capture in flight",
                                3: "SIGTRAP blocked",
                                4: "Would block / restart",
                                5: "Signal failed",
                            }.get(value["Flags"], "Stack unavailable"),
                        )
            if kind == "agent":
                if value.get("type") == "error":
                    raise RuntimeError(value.get("description", "Agent error"))
                if value.get("type") == "send" and value["payload"].get("type") == "capture":
                    captures[value["payload"]["tid"]] = (value["payload"], data)
            for tid, (k, started, reported) in list(pending.items()):
                if tid in captures:
                    c, d = captures.pop(tid)
                    r = c["registers"]
                    s = k["Saved"]
                    if any(int(r[n], 16) != s[i] for n, i in [("pc", 16), ("sp", 19), ("rax", 10)]):
                        raise RuntimeError("Frida context does not match syscall exit")
                    output(k, c, d)
                    write(f"ack {tid} {k['Exited']}")
                    del pending[tid]
                elif not reported and time.monotonic() - started > 3:
                    output(k, reason="Waiting for signal delivery")
                    pending[tid][2] = True
    finally:
        stop.set()
        if helper:
            try:
                helper.stdin.close()
            except (OSError, ValueError):
                pass
            try:
                helper.wait(timeout=4)
            except subprocess.TimeoutExpired:
                helper.kill()
                helper.wait()
        if script:
            try:
                script.exports_sync.stop()
            except frida.InvalidOperationError:
                pass
        cancellation = frida.Cancellable()
        timer = threading.Timer(2, cancellation.cancel)
        timer.start()
        try:
            with cancellation:
                session.detach()
        except (frida.OperationCancelledError, frida.InvalidOperationError):
            pass
        finally:
            timer.cancel()


if __name__ == "__main__":

    def emit(value):
        print(json.dumps(value), flush=True)

    try:
        run(json.loads(sys.stdin.readline()), emit)
    except Exception as error:
        emit({"type": "error", "error": str(error)})
        sys.exit(1)
