"""Coletor 2: snapshot do sistema atual (Linux): /proc, stat, systemctl, journalctl.

Somente leitura. Permissões são coletadas por CONTEXTO (arquivos ligados a processos/serviços,
diretórios pai, arquivos sensíveis e alguns diretórios de interesse), não por varredura total.
"""
from __future__ import annotations
import grp, os, pwd, re, shutil, socket, stat, subprocess, sys
from datetime import datetime
from pathlib import Path
from ..models import Process, FileMeta, Service, Snapshot
from ..utils import split_cmd, paths_in, SENSITIVE, CONTEXT_DIRS
from .dataset import parse_journal_lines

_uid, _gid = {}, {}


def _user(uid: int) -> str:
    if uid not in _uid:
        try: _uid[uid] = pwd.getpwuid(uid).pw_name
        except KeyError: _uid[uid] = str(uid)
    return _uid[uid]


def _group(gid: int) -> str:
    if gid not in _gid:
        try: _gid[gid] = grp.getgrgid(gid).gr_name
        except KeyError: _gid[gid] = str(gid)
    return _gid[gid]


def read_processes(warnings) -> list:
    try:
        btime = next(int(l.split()[1]) for l in open("/proc/stat") if l.startswith("btime"))
    except Exception:
        btime = int(datetime.now().timestamp()); warnings.append("btime indisponível: timestamps de processos aproximados")
    ticks = os.sysconf("SC_CLK_TCK")
    out, denied = [], 0
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        pid = int(d)
        try:
            raw = Path(f"/proc/{pid}/stat").read_bytes().decode(errors="replace")
            rp = raw.rfind(")")
            rest = raw[rp + 2:].split()
            state, ppid, start = rest[0], int(rest[1]), int(rest[19])
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
            if not cmdline:                      # thread de kernel
                continue
            uid = next(int(l.split()[1]) for l in Path(f"/proc/{pid}/status").read_text().splitlines() if l.startswith("Uid:"))
        except (FileNotFoundError, ProcessLookupError, StopIteration, IndexError, ValueError):
            continue                             # processo terminou durante a coleta
        except PermissionError:
            denied += 1; continue
        tok, args, script = split_cmd(cmdline)
        try: exe = os.readlink(f"/proc/{pid}/exe")
        except OSError: exe = tok
        if script and not script.startswith("/"):
            try: script = os.path.normpath(os.path.join(os.readlink(f"/proc/{pid}/cwd"), script))
            except OSError: pass
        ts = datetime.fromtimestamp(btime + start / ticks)
        out.append(Process(ts, pid, ppid, _user(uid), state, cmdline, exe, args, script))
    if denied:
        warnings.append(f"{denied} processo(s) sem permissão de leitura em /proc (execute como root para visão completa)")
    return out


def _systemctl(*args):
    return subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=15)


def read_services(warnings) -> list:
    if not shutil.which("systemctl"):
        warnings.append("systemctl não encontrado: serviços não coletados"); return []
    try:
        r = _systemctl("list-units", "--type=service", "--state=running", "--no-legend", "--plain", "--no-pager")
    except Exception as e:
        warnings.append(f"systemctl falhou: {e}"); return []
    if r.returncode != 0 or not r.stdout.strip():
        warnings.append("systemd indisponível/sem serviços em execução (container?): serviços não coletados"); return []
    out = []
    for line in r.stdout.splitlines():
        unit = line.split()[0] if line.split() else ""
        if not unit.endswith(".service"):
            continue
        try:
            sh = _systemctl("show", unit, "-p", "User", "-p", "ExecStart", "-p", "MainPID", "--no-pager").stdout
        except Exception:
            continue
        kv = dict(l.split("=", 1) for l in sh.splitlines() if "=" in l)
        m = re.search(r"argv\[\]=(.*?) ;", kv.get("ExecStart", ""))
        execstart = m.group(1).strip() if m else ""
        if not execstart:
            continue
        out.append(Service(unit, "running", kv.get("User") or "root", execstart, execstart.split()[0],
                           unit.rsplit(".", 1)[0], int(kv.get("MainPID") or 0)))
    return out


def _stat(path: str):
    try:
        st = os.stat(path)
    except OSError:
        return None
    return FileMeta(path, "directory" if stat.S_ISDIR(st.st_mode) else "file", _user(st.st_uid), _group(st.st_gid),
                    st.st_mode & 0o7777, datetime.fromtimestamp(st.st_mtime))


def read_permissions(procs, services, warnings) -> dict:
    wanted = set(SENSITIVE)
    for s in services:
        wanted.update(paths_in(s.execstart))
    for p in procs:
        wanted.update(x for x in (p.exe, p.script, *paths_in(p.cmd)) if x.startswith("/"))
    wanted.update(os.path.dirname(w) for w in list(wanted) if os.path.dirname(w) not in ("", "/"))
    count = 0
    for base in CONTEXT_DIRS + ("/etc/crontab",):
        if not os.path.exists(base):
            continue
        wanted.add(base)
        if os.path.isdir(base):
            depth0 = base.rstrip("/").count("/")
            for root, dirs, files in os.walk(base):
                if root.count("/") - depth0 >= 2:
                    dirs[:] = []
                for n in dirs + files:
                    wanted.add(os.path.join(root, n)); count += 1
                if count > 1500:
                    warnings.append(f"diretório de contexto {base} truncado em 1500 entradas"); break
    perms = {}
    for w in wanted:
        m = _stat(w)
        if m:
            perms[w] = m
    return perms


def read_journal(year: int, warnings) -> list:
    lines = []
    if shutil.which("journalctl"):
        try:
            r = subprocess.run(["journalctl", "--no-pager", "-o", "short", "-n", "500"], capture_output=True, text=True, timeout=20)
            if r.returncode == 0:
                lines = r.stdout.splitlines()
        except Exception:
            pass
    if not lines:
        for f in ("/var/log/syslog", "/var/log/auth.log", "/var/log/messages"):
            try: lines += Path(f).read_text(errors="replace").splitlines()[-500:]
            except OSError: pass
    if not lines:
        warnings.append("nenhum log legível (journalctl/syslog): correlação temporal limitada")
    return parse_journal_lines(lines, year)


def collect_live() -> Snapshot:
    if not sys.platform.startswith("linux") or not os.path.isdir("/proc"):
        raise RuntimeError("o modo --live requer Linux com /proc")
    warnings: list = []
    procs = read_processes(warnings)
    services = read_services(warnings)
    perms = read_permissions(procs, services, warnings)
    events = read_journal(datetime.now().year, warnings)
    meta = {"dataset_type": "live_snapshot", "scenario": "live", "level": "-", "host": socket.gethostname(),
            "generated_at": datetime.now().isoformat(timespec="seconds"), "euid": os.geteuid()}
    if os.geteuid() != 0:
        warnings.append("executando sem root: visão parcial de /proc e de alguns arquivos")
    return Snapshot("live", socket.gethostname(), procs, perms, services, events, meta, warnings)
