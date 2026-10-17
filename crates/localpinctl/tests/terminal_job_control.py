"""Exercise only a fresh synthetic PTY and the Rust test executable passed in."""

import fcntl
import os
import select
import signal
import sys
import termios
import time

def wait_status(pid, timeout=2):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        found, status = os.waitpid(pid, os.WNOHANG | os.WUNTRACED)
        if found:
            return status
        time.sleep(0.01)
    raise AssertionError("terminal child did not react within two seconds")


def run_case(case):
    master, slave = os.openpty()
    original = termios.tcgetattr(slave)
    command_r, command_w = os.pipe()
    report_r, report_w = os.pipe()
    supervisor = os.fork()
    if supervisor == 0:
        os.close(command_w)
        os.close(report_r)
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        gate_r, gate_w = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(gate_w)
            os.setpgid(0, 0)
            os.read(gate_r, 1)
            for descriptor in (0, 1, 2):
                os.dup2(slave, descriptor)
            environment = dict(os.environ, LOCALPIN_CLI_JOB_CONTROL_CHILD="1")
            os.execve(sys.argv[1], [sys.argv[1]], environment)
        os.close(gate_r)
        os.setpgid(child, child)
        os.tcsetpgrp(slave, child)
        os.write(gate_w, b"g")
        os.write(report_w, f"{child}\n".encode())
        reaped = False
        failed = None
        try:
            os.read(command_r, 1)
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTTOU})
            if case == "foreground-loss":
                os.tcsetpgrp(slave, os.getpgrp())
            else:
                os.kill(child, getattr(signal, case))
            status = wait_status(child)
            reaped = not os.WIFSTOPPED(status)
            assert termios.tcgetattr(slave) == original, "terminal remained in private mode"
            if case == "foreground-loss":
                assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, status
            else:
                assert os.WIFSTOPPED(status) and os.WSTOPSIG(status) == getattr(signal, case), status
                os.kill(child, signal.SIGCONT)
                status = wait_status(child)
                reaped = not os.WIFSTOPPED(status)
                assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, status
        except BaseException as error:
            failed = f"{case}: {error}"
        finally:
            if not reaped:
                os.tcsetpgrp(slave, child)
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
            # Never leave even the test's private terminal in raw mode on failure.
            termios.tcsetattr(slave, termios.TCSANOW, original)
        os.write(report_w, (failed or f"{case}: restored").encode())
        os._exit(1 if failed else 0)
    os.close(command_r)
    os.close(report_w)
    output = b""
    child_pid = None
    supervisor_reaped = False
    try:
        assert select.select([report_r], [], [], 3)[0], "no child process identity"
        child_pid = int(os.read(report_r, 64))
        deadline = time.monotonic() + 3
        while b"Type yes: " not in output:
            remaining = deadline - time.monotonic()
            assert remaining > 0 and select.select([master], [], [], remaining)[0], "no private prompt"
            output += os.read(master, 4096)
        # No input is supplied after foreground loss: the CLI must notice the
        # ownership change while the terminal itself remains completely silent.
        os.write(command_w, b"r")
        assert select.select([report_r], [], [], 4)[0], "no child report"
        report = os.read(report_r, 4096).decode()
        _, status = os.waitpid(supervisor, 0)
        supervisor_reaped = True
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, report
    finally:
        os.close(command_w)
        if not supervisor_reaped:
            if child_pid is not None:
                try:
                    os.killpg(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                wait_status(supervisor)
            except AssertionError:
                os.kill(supervisor, signal.SIGKILL)
                os.waitpid(supervisor, 0)
            termios.tcsetattr(slave, termios.TCSANOW, original)
        os.close(report_r)
        os.close(master)
        os.close(slave)


for scenario in ("foreground-loss", "SIGTTIN", "SIGTTOU"):
    run_case(scenario)
