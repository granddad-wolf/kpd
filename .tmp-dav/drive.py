#!/usr/bin/env python3
"""Drive the kpd TUI under a pty against the wsgidav server and assert on screen.

Usage: drive.py <target> <mode>   modes: save | reveal | conflict | badauth
Env: KPD_TEST_PASSWORD (master password), KPD_WEBDAV_USER, KPD_WEBDAV_PASS,
     DAV_SECOND (a different kdbx used to simulate a concurrent change).
"""
import fcntl
import os
import pty
import re
import select
import shutil
import signal
import struct
import sys
import termios
import time

ROWS, COLS = 40, 120
BIN = "/home/rdpadmin/kpd/target/release/kpd"
TARGET = sys.argv[1]
MODE = sys.argv[2]
PASSWORD = os.environ["KPD_TEST_PASSWORD"]
SECOND = os.environ.get("DAV_SECOND", "")
ANSI = re.compile(rb"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*\x07)")

env = dict(os.environ)
env["TERM"] = "xterm-256color"

pid, fd = pty.fork()
if pid == 0:
    os.chdir("/home/rdpadmin/kpd")
    if TARGET.startswith("http"):
        argv = [BIN, "open", "--webdav", TARGET]
    else:
        argv = [BIN, "open", TARGET]
    os.execvpe(BIN, argv, env)

fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
buf = bytearray()


def drain(seconds):
    start = len(buf)
    end = time.time() + seconds
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            buf.extend(data)
    return ANSI.sub(b"", bytes(buf[start:])).decode("utf-8", "replace")


def send(keys, seconds=0.6):
    os.write(fd, keys.encode())
    return drain(seconds)


def fail(message, step, screen):
    print(f"FAIL [{MODE}] {message} (step: {step})")
    print("---- screen tail ----")
    print(screen[-1500:])
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    sys.exit(1)


try:
    screen = drain(1.5)
    if "password" not in screen.lower():
        fail("unlock screen did not render", "startup", screen)

    screen = send(PASSWORD + "\r", 4.0)

    if MODE == "badauth":
        if "cloud fetch failed" not in screen:
            fail("expected a fetch failure with bad credentials", "unlock", screen)
        if "unlocked" in screen:
            fail("bad credentials still unlocked", "unlock", screen)
        send("q", 0.3)
    elif "unlocked" not in screen or "entries" not in screen:
        fail("database did not unlock over WebDAV", "unlock", screen)
    else:
        if TARGET.startswith("http") and ("loaded" not in screen or "http://" not in screen):
            fail("missing 'loaded from <url>' status", "unlock", screen)

        if MODE == "reveal":
            send("\t", 0.4)
            send("\r", 0.5)
            screen = send("r", 0.8)
            send("q", 0.4)
            if "wsgidav-e2e-pass" not in screen:
                fail("saved entry password is not visible after reveal", "reveal", screen)
        else:
            if MODE == "conflict":
                shutil.copyfile(SECOND, "/home/rdpadmin/kpd/.tmp-dav/root/vault.kdbx")

            send("e", 0.4)
            send("\x7f" * 16, 0.4)
            send("wsgidav-e2e-pass", 0.4)
            send("\r", 0.4)
            send("\x13", 0.4)  # Ctrl+S
            screen = send("y", 4.0)

            if MODE == "save":
                if "bytes to http" not in screen:
                    fail("expected a successful WebDAV save", "save", screen)
            else:
                if "changed remotely" not in screen:
                    fail("expected a revision conflict from the server", "save", screen)
                if "bytes to http" in screen:
                    fail("a refused save still claimed success", "save", screen)

            send("q", 0.5)
finally:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    open(f"/home/rdpadmin/kpd/.tmp-dav/{MODE}-screen.txt", "wb").write(bytes(buf))

print(f"PASS [{MODE}] {TARGET}")
