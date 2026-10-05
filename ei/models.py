"""Modelos de dados normalizados (resultado da etapa NORMALIZAÇÃO)."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Process:
    ts: datetime; pid: int; ppid: int; user: str; stat: str; cmd: str
    exe: str = ""; args: list = field(default_factory=list); script: str = ""


@dataclass
class FileMeta:
    path: str; type: str; owner: str; group: str; mode: int; mtime: datetime


@dataclass
class Service:
    unit: str; active: str; user: str; execstart: str; exe: str; name: str
    main_pid: int = 0          # só na coleta live (systemctl show MainPID)


@dataclass
class LogEvent:
    ts: datetime; host: str; source: str; pid: int | None; message: str


@dataclass
class Snapshot:
    """Conjunto normalizado produzido por qualquer coletor (dataset, live ou script)."""
    mode: str
    source: str
    processes: list
    perms: dict            # path -> FileMeta
    services: list
    events: list
    meta: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)


@dataclass
class Finding:
    title: str
    severity: str                       # high | medium | low | info | inconclusive
    evidence: list
    interpretation: str
    hypothesis: str
    missing: list                       # evidência ausente
    against: list = field(default_factory=list)     # contra-evidências
    correlation: str = ""
    refs: dict = field(default_factory=dict)        # {"pids":[], "files":[], "services":[]}
    id: str = ""


SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "inconclusive": 4}
