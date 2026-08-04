#!/usr/bin/env python3
"""
ssh_exec.py — reusable SSH fleet transport (keys or password, sudo, parallel).

Extracted from linux-audit. Handles the parts that are annoying to get right:

  * key / agent / ssh_config auth, or password auth via sshpass
  * sudo escalation, passwordless or password-over-stdin
  * running a whole script on the remote host in ONE round trip
  * parallel execution with per-host isolation: one dead host never kills a run
  * failures returned as data (with the real ssh reason), not exceptions

No third-party dependencies. Uses the system `ssh` binary, so ~/.ssh/config,
ProxyJump, ControlMaster etc. all keep working.

Quick use
---------
    from ssh_exec import SSHConfig, run_fleet, parse_hosts

    cfg = SSHConfig(user="local.user", ask_ssh_pass=True, sudo_pass_same_as_ssh=True)
    cfg.resolve_passwords()                      # prompts once, reuses for all

    hosts = parse_hosts("hosts.txt")
    for res in run_fleet(hosts, "hostname; id", cfg, workers=8):
        if res.ok:
            print(res.host, "->", res.stdout.strip())
        else:
            print(res.host, "FAILED:", res.error)

Security notes
--------------
  * Passwords are passed via stdin / the SSHPASS env var, never argv (argv is
    world-readable via /proc on most systems).
  * Default StrictHostKeyChecking=accept-new: new keys accepted, CHANGED keys
    refused. Use host_key_checking="no" only on trusted internal networks.
  * The password-sudo path stages the script to a 0600 temp file because stdin
    is already occupied by the sudo password. See _run_sudo_pass().
"""

import base64
import concurrent.futures as cf
import getpass
import os
import re
import shutil
import subprocess

__all__ = ["SSHConfig", "Result", "parse_hosts", "run_one", "run_fleet"]


class Result:
    """Outcome for a single host. Failures are data, not exceptions."""

    __slots__ = ("host", "ok", "stdout", "stderr", "rc", "error")

    def __init__(self, host, ok=False, stdout="", stderr="", rc=None, error=None):
        self.host, self.ok = host, ok
        self.stdout, self.stderr, self.rc = stdout, stderr, rc
        self.error = error

    def __repr__(self):
        return "<Result %s %s rc=%s%s>" % (
            self.host, "ok" if self.ok else "FAIL", self.rc,
            " error=%r" % self.error if self.error else "")


class SSHConfig:
    """Connection + escalation policy for a fleet run."""

    def __init__(self, user=None, port=None, identity=None,
                 escalate="sudo",                 # "sudo" | "none"
                 ask_ssh_pass=False, ssh_pass_env=None,
                 ask_sudo_pass=False, sudo_pass_same_as_ssh=False,
                 host_key_checking="accept-new", ssh_opts=None,
                 connect_timeout=10, cmd_timeout=120):
        self.user, self.port, self.identity = user, port, identity
        self.escalate = escalate
        self.ask_ssh_pass, self.ssh_pass_env = ask_ssh_pass, ssh_pass_env
        self.ask_sudo_pass = ask_sudo_pass
        self.sudo_pass_same_as_ssh = sudo_pass_same_as_ssh
        self.host_key_checking = host_key_checking
        self.ssh_opts = list(ssh_opts or [])
        self.connect_timeout, self.cmd_timeout = connect_timeout, cmd_timeout
        self.ssh_pass = None
        self.sudo_pass = None

    def resolve_passwords(self, ssh_pass=None, sudo_pass=None):
        """Prompt once (or read env) and reuse for every host.

        Correct for a shared domain/service account, which is the common case.
        Pass explicit values to bypass prompting (tests, or your own UI).
        """
        if ssh_pass is not None:
            self.ssh_pass = ssh_pass
        elif self.ssh_pass_env:
            self.ssh_pass = os.environ.get(self.ssh_pass_env)
            if self.ssh_pass is None:
                raise RuntimeError("env var %s is not set" % self.ssh_pass_env)
        elif self.ask_ssh_pass:
            self.ssh_pass = getpass.getpass("SSH password (all hosts): ")

        if self.ssh_pass is not None and not shutil.which("sshpass"):
            raise RuntimeError(
                "password SSH login needs 'sshpass' (apt/dnf install sshpass), "
                "or use key-based auth")

        if self.escalate == "sudo":
            if sudo_pass is not None:
                self.sudo_pass = sudo_pass
            elif self.sudo_pass_same_as_ssh:
                if self.ssh_pass is None:
                    raise RuntimeError(
                        "sudo_pass_same_as_ssh requires an SSH password")
                self.sudo_pass = self.ssh_pass
            elif self.ask_sudo_pass:
                self.sudo_pass = getpass.getpass("sudo password (all hosts): ")
        return self


def parse_hosts(path):
    """Parse a host list: `host`, `user@host`, `host:port`, `user@host:port`.

    Blank lines and #comments (including inline) are ignored.
    Returns [{"target","user","port"}]. IPv6-safe: only a trailing :digits is
    treated as a port.
    """
    out = []
    with open(path) as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            user = port = None
            if "@" in line:
                user, line = line.split("@", 1)
            m = re.match(r"^(.*):(\d+)$", line)
            if m and m.group(1).count(":") == 0:
                line, port = m.group(1), m.group(2)
            out.append({"target": line.strip(), "user": user, "port": port})
    return out


def host_label(h):
    return ((h["user"] + "@") if h.get("user") else "") + h["target"] + \
           ((":" + str(h["port"])) if h.get("port") else "")


def _base_cmd(host, cfg):
    cmd = []
    if cfg.ssh_pass is not None:
        cmd += ["sshpass", "-e"]          # reads SSHPASS env var, never argv
    cmd += ["ssh",
            "-o", "ConnectTimeout=%d" % cfg.connect_timeout,
            "-o", "StrictHostKeyChecking=%s" % cfg.host_key_checking]
    if cfg.ssh_pass is None:
        cmd += ["-o", "BatchMode=yes"]    # fail fast instead of prompting
    else:
        cmd += ["-o", "PubkeyAuthentication=no",
                "-o", "PreferredAuthentications=password,keyboard-interactive"]
    if cfg.identity:
        cmd += ["-i", cfg.identity]
    port = host.get("port") or cfg.port
    if port:
        cmd += ["-p", str(port)]
    for o in cfg.ssh_opts:
        cmd += ["-o", o]
    user = host.get("user") or cfg.user
    cmd.append(("%s@%s" % (user, host["target"])) if user else host["target"])
    return cmd


def _exec(cmd, data, timeout, env):
    return subprocess.run(cmd, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, env=env)


def run_one(host, script, cfg):
    """Run `script` (a shell script, as text) on one host. Returns Result."""
    label = host_label(host)
    base = _base_cmd(host, cfg)
    env = {**os.environ, "SSHPASS": cfg.ssh_pass} if cfg.ssh_pass is not None else None
    data = script.encode() if isinstance(script, str) else script

    try:
        if cfg.escalate == "none":
            r = _exec(base + ["bash -s"], data, cfg.cmd_timeout, env)
            return _result(label, r)

        if cfg.sudo_pass is None:
            # passwordless sudo: script rides in on stdin, one round trip
            r = _exec(base + ["sudo -n bash -s"], data, cfg.cmd_timeout, env)
            err = r.stderr.decode(errors="replace")
            if r.returncode != 0 and "password is required" in err.lower():
                return Result(label, error="passwordless sudo unavailable; "
                                           "supply a sudo password")
            return _result(label, r)

        return _run_sudo_pass(label, base, data, cfg, env)

    except subprocess.TimeoutExpired:
        return Result(label, error="timed out after %ds" % cfg.cmd_timeout)
    except FileNotFoundError as e:
        return Result(label, error="missing binary: %s" % e)
    except Exception as e:  # noqa: BLE001 - a bad host must not kill the fleet
        return Result(label, error="%s: %s" % (type(e).__name__, e))


def _run_sudo_pass(label, base, data, cfg, env):
    """Password sudo needs TWO round trips, and this is the reason why.

    `sudo -S` reads the password from stdin. But `bash -s` also wants the script
    on stdin. They collide: you cannot pipe both. So stage the script to a 0600
    temp file first, then run it under sudo with only the password on stdin.
    """
    token = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
    tmp = "/tmp/.rex_%s.sh" % token

    stage = _exec(base + ["umask 077; cat > %s" % tmp], data, cfg.cmd_timeout, env)
    if stage.returncode != 0:
        return Result(label, error="staging failed: " +
                      stage.stderr.decode(errors="replace").strip())

    # -p '' suppresses the sudo prompt so it never pollutes stdout
    run = "sudo -S -p '' bash %s; rc=$?; rm -f %s; exit $rc" % (tmp, tmp)
    r = _exec(base + [run], (cfg.sudo_pass + "\n").encode(), cfg.cmd_timeout, env)
    return _result(label, r)


def _result(label, r):
    out = r.stdout.decode(errors="replace")
    err = r.stderr.decode(errors="replace")
    if r.returncode == 0:
        return Result(label, ok=True, stdout=out, stderr=err, rc=r.returncode)
    return Result(label, ok=False, stdout=out, stderr=err, rc=r.returncode,
                  error=(err.strip().splitlines() or ["exit %d" % r.returncode])[0])


def run_fleet(hosts, script, cfg, workers=8, on_result=None):
    """Run `script` on every host in parallel. Yields Result objects.

    Never raises for a host-level problem: a dead host yields a Result with
    ok=False and .error set, and the rest of the fleet carries on.
    """
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(run_one, h, script, cfg): h for h in hosts}
        for fut in cf.as_completed(futs):
            res = fut.result()
            if on_result:
                on_result(res)
            yield res
