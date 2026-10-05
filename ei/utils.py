"""Utilitários compartilhados: parsing de comandos, permissões e árvore de processos."""
from __future__ import annotations
import os, re
from datetime import datetime
from .models import Process, FileMeta

INTERP = re.compile(r"^(python[\d.]*|bash|sh|dash|perl|ruby|node)$")
USER_DIRS = ("/home/", "/tmp/", "/var/tmp/", "/dev/shm/")
SYSTEM_DIRS = ("/usr/", "/etc/", "/opt/", "/bin/", "/sbin/")
SENSITIVE = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers")
CONTEXT_DIRS = ("/opt", "/usr/local/bin", "/etc/cron.d", "/etc/cron.daily", "/etc/systemd/system")


def split_cmd(cmd: str):
    """cmd -> (executável, argumentos, script quando o executável é um interpretador)."""
    toks = cmd.split()
    exe = toks[0] if toks else ""
    args = toks[1:]
    script = ""
    if INTERP.match(os.path.basename(exe)):
        script = next((a for a in args if not a.startswith("-")), "")
    return exe, args, script


def naive(dt: datetime) -> datetime:
    return dt.replace(tzinfo=None)


def label(p: Process) -> str:
    return f"{p.pid}:{p.cmd[:32]}({p.user})"


def build_process_tree(procs):
    by_pid = {p.pid: p for p in procs}
    kids: dict = {}
    for p in procs:
        kids.setdefault(p.ppid, []).append(p)
    return by_pid, kids


def ancestry(p: Process, by_pid) -> list:
    chain, seen = [p], {p.pid}
    while chain[-1].ppid in by_pid and chain[-1].ppid not in seen:
        nxt = by_pid[chain[-1].ppid]
        chain.append(nxt); seen.add(nxt.pid)
    return list(reversed(chain))


def descendants(p: Process, kids) -> list:
    out, stack = [], list(kids.get(p.pid, []))
    while stack:
        c = stack.pop(); out.append(c); stack.extend(kids.get(c.pid, []))
    return out


def paths_in(text: str) -> list:
    return re.findall(r"(?<![\w.@-])(/[\w./-]+)", text)


def unprivileged_write_reasons(m: FileMeta) -> list:
    """Por que um usuário não privilegiado poderia modificar este recurso?"""
    r = []
    sticky = bool(m.mode & 0o1000) and m.type == "directory"
    if m.mode & 0o002 and not sticky:
        r.append(f"world-writable (o+w, modo {m.mode & 0o777:04o})")
    if m.mode & 0o020 and m.group != "root":
        r.append(f"gravável pelo grupo '{m.group}' (g+w)")
    if m.owner != "root":
        r.append(f"dono é '{m.owner}' (não privilegiado)")
    return r


def meta_str(m: FileMeta) -> str:
    return f"{m.path} {m.type} {m.owner}:{m.group} modo={m.mode & 0o7777:04o} mtime={m.mtime:%Y-%m-%d %H:%M:%S}"
