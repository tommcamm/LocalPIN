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


def run_case(case, input_kind):
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
            environment = dict(os.environ, LOCALPIN_CLI_JOB_CONTROL_CHILD=input_kind)
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
        prompt = {"choice": b"Choose [1]: ", "masked": b"New credential: ", "secret": b"Type yes: "}[input_kind]
        while prompt not in output:
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


for kind in ("secret", "choice", "masked"):
    for scenario in ("foreground-loss", "SIGTTIN", "SIGTTOU"):
        run_case(scenario, kind)


def run_form_case(*, term, no_color=False):
    """Exercise the shared real terminal form, without opening a broker."""
    master, slave = os.openpty()
    original = termios.tcgetattr(slave)
    child = os.fork()
    if child == 0:
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        for descriptor in (0, 1, 2):
            os.dup2(slave, descriptor)
        environment = dict(os.environ, TERM=term, LOCALPIN_CLI_JOB_CONTROL_CHILD="form")
        environment.pop("NO_COLOR", None)
        if no_color:
            environment["NO_COLOR"] = ""
        os.execve(sys.argv[1], [sys.argv[1]], environment)
    output = b""
    pending = b""
    secret = b"  Demo phrase!? "
    steps = [(b"Type [1] (q to cancel): ", b"2"),
             (b"New passcode      ", secret), (b"Confirm passcode  ", secret)]
    sent = 0
    reaped = False
    try:
        deadline = time.monotonic() + 3
        while True:
            found, status = os.waitpid(child, os.WNOHANG)
            if found:
                reaped = True
                assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, output
                break
            assert time.monotonic() < deadline, "credential form did not complete promptly"
            if select.select([master], [], [], .05)[0]:
                data = os.read(master, 4096)
                output += data
                pending += data
            if sent < len(steps) and steps[sent][0] in pending:
                os.write(master, steps[sent][1] + b"\n")
                sent += 1
                pending = b""
        while select.select([master], [], [], 0)[0]:
            data = os.read(master, 4096)
            if not data:
                break
            output += data
        assert sent == len(steps), "form stopped before confirmation"
        assert secret not in output and output.count(b"*") == len(secret) * 2, output
        assert b"Credential ready. Verify your account password to save." in output, output
        assert b"Protection  Software" in output, output
        assert termios.tcgetattr(slave) == original, "form did not restore terminal"
        expect_color = term != "dumb" and not no_color
        assert (b"\x1b[1;36mLocalPIN\x1b[0m" in output) == expect_color, output
        if not expect_color:
            assert b"\x1b" not in output, output
    finally:
        if not reaped:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        termios.tcsetattr(slave, termios.TCSANOW, original)
        os.close(master)
        os.close(slave)


run_form_case(term="xterm-256color")
run_form_case(term="xterm-256color", no_color=True)
run_form_case(term="dumb")


def run_menu_case(*, term, no_color=False, redirected=False):
    """Open the real CLI menu, then select Exit; no account operation runs."""
    master, slave = os.openpty()
    original = termios.tcgetattr(slave)
    output_r, output_w = os.pipe() if redirected else (None, None)
    child = os.fork()
    if child == 0:
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        os.dup2(slave, 0)
        os.dup2(output_w if redirected else slave, 1)
        os.dup2(slave, 2)
        environment = {"TERM": term}
        if no_color:
            environment["NO_COLOR"] = ""
        os.execve(sys.argv[2], [sys.argv[2]], environment)
    if redirected:
        os.close(output_w)
    reader = output_r if redirected else master
    output = b""
    selected_exit = False
    reaped = False
    try:
        deadline = time.monotonic() + 3
        while True:
            found, status = os.waitpid(child, os.WNOHANG)
            if found:
                reaped = True
                assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, status
                break
            remaining = deadline - time.monotonic()
            assert remaining > 0, "menu did not exit promptly"
            if select.select([reader], [], [], min(remaining, 0.1))[0]:
                output += os.read(reader, 4096)
            if not redirected and not selected_exit and b"Choose a number" in output:
                os.write(master, b"7\n")
                selected_exit = True
        # The child can exit between select calls; drain its final buffered text.
        while select.select([reader], [], [], 0)[0]:
            chunk = os.read(reader, 4096)
            if not chunk:
                break
            output += chunk
        assert termios.tcgetattr(slave) == original, "menu did not restore the terminal"
        if redirected:
            assert b"Usage: localpin [command]" in output
            assert b"Choose a number" not in output
        else:
            assert selected_exit and b"Set up or resume setup" in output
        expect_color = not redirected and term != "dumb" and not no_color
        assert (b"\x1b[1;36mLocalPIN\x1b[0m" in output) == expect_color, output
        if not expect_color:
            assert b"\x1b" not in output, output
    finally:
        if not reaped:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        termios.tcsetattr(slave, termios.TCSANOW, original)
        if redirected:
            os.close(output_r)
        os.close(master)
        os.close(slave)


# Root intentionally gets administrator help instead of the owner menu. These
# cases exercise only the normal-user menu and never invoke its setup action.
if os.getuid() != 0:
    run_menu_case(term="xterm-256color")
    run_menu_case(term="xterm-256color", no_color=True)
    run_menu_case(term="dumb")
    run_menu_case(term="xterm-256color", redirected=True)
