"""Coletor 1: lê um diretório de dataset (processes.csv, permissions.csv, services.txt, journal.log)."""
from __future__ import annotations
import csv, json, re
from datetime import datetime
from pathlib import Path
from ..models import Process, FileMeta, Service, LogEvent, Snapshot
from ..utils import split_cmd, naive

REQUIRED = ("processes.csv", "permissions.csv", "services.txt")
LOG_RE = re.compile(r"^(\w{3})\s+(\d+)\s+(\d\d:\d\d:\d\d)\s+(\S+)\s+([^\[:]+)(?:\[(\d+)\])?:\s*(.*)$")
ISO_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?(?:[+-]\d\d:?\d\d|Z)?\s+(\S+)\s+([^\[:]+)(?:\[(\d+)\])?:\s*(.*)$")


def load_metadata(path) -> dict:
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def load_processes(path) -> list:
    out = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            exe, args, script = split_cmd(r["cmd"])
            out.append(Process(naive(datetime.fromisoformat(r["timestamp"])), int(r["pid"]), int(r["ppid"]),
                               r["user"], r["stat"], r["cmd"], exe, args, script))
    return out


def load_permissions(path) -> dict:
    out = {}
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            out[r["path"]] = FileMeta(r["path"], r["type"], r["owner"], r["group"], int(r["mode"], 8),
                                      naive(datetime.fromisoformat(r["mtime"])))
    return out


def load_services(path) -> list:
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("UNIT"):
            continue
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        unit, active, user, ex = parts
        out.append(Service(unit, active, user, ex, ex.split()[0], unit.rsplit(".", 1)[0]))
    return out


def parse_journal_lines(lines, year: int) -> list:
    """Aceita formato syslog clássico ('Sep 14 09:00:00 host proc[pid]: msg') e ISO-8601."""
    out = []
    for line in lines:
        m = LOG_RE.match(line)
        if m:
            mon, day, t, host, src, pid, msg = m.groups()
            try:
                ts = datetime.strptime(f"{year} {mon} {day} {t}", "%Y %b %d %H:%M:%S")
            except ValueError:
                continue
            out.append(LogEvent(ts, host, src.strip(), int(pid) if pid else None, msg))
            continue
        m = ISO_RE.match(line)
        if m:
            ts, host, src, pid, msg = m.groups()
            out.append(LogEvent(datetime.fromisoformat(ts), host, src.strip(), int(pid) if pid else None, msg))
    return out


def year_from_meta(meta: dict) -> int:
    try:
        return int(str(meta.get("generated_at", ""))[:4])
    except ValueError:
        return datetime.now().year


def find_dataset_root(base: Path):
    """Localiza o diretório que contém os arquivos obrigatórios (a própria base ou uma subpasta)."""
    cands = [base] + sorted(p.parent for p in base.rglob("processes.csv"))
    for c in cands:
        if all((c / n).exists() for n in REQUIRED):
            return c
    return None


def collect_dataset(directory) -> Snapshot:
    base = Path(directory)
    if not base.is_dir():
        raise FileNotFoundError(f"diretório de dataset não encontrado: {directory}")
    root = find_dataset_root(base)
    if root is None:
        raise FileNotFoundError(f"dataset inválido em {directory}: esperado {', '.join(REQUIRED)} (journal.log opcional)")
    meta = load_metadata(root / "metadata.json")
    warnings = []
    jl = root / "journal.log"
    events = parse_journal_lines(jl.read_text(encoding="utf-8").splitlines(), year_from_meta(meta)) if jl.exists() else []
    if not jl.exists():
        warnings.append("journal.log ausente: correlação com logs indisponível")
    return Snapshot("dataset", str(root), load_processes(root / "processes.csv"), load_permissions(root / "permissions.csv"),
                    load_services(root / "services.txt"), events, meta, warnings)
