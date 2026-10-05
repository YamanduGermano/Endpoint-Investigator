"""C3: processo + serviço + log -> linha do tempo e checagem de consistência."""
from __future__ import annotations
import os, re
from ..models import Finding
from ..utils import label

INTEREST = re.compile(r"Failed password|authentication failure|segfault|COMMAND=|session opened for user root")


def correlate_timeline(snap, by_pid, relevant_pids):
    rows, findings = [], []
    show_all_logs = len(snap.events) <= 200
    for p in snap.processes:
        if p.pid in relevant_pids:
            rows.append((p.ts, "PROC", f"{label(p)} ppid={p.ppid}", ""))
    for e in snap.events:
        link, linked = "", False
        m = re.match(r"Started (\S+)", e.message)
        if m:
            u = next((s for s in snap.services if s.unit == m.group(1)), None)
            if u:
                link, linked = f"-> serviço {u.unit} (user={u.user})", True
        if e.pid and e.pid in by_pid:
            p = by_pid[e.pid]; linked = True
            link = f"-> PID {p.pid} '{p.cmd[:30]}' user={p.user}"
            ln, pn = e.source, os.path.basename(p.exe).rstrip(":")
            names = {pn, os.path.basename(p.script)} if p.script else {pn}
            if pn == "init":
                names.add("systemd")                 # /sbin/init costuma ser link para o systemd
            if not any(ln in n or n in ln for n in names if n):
                findings.append(Finding(
                    f"Log e processo com mesmo PID mas nomes diferentes (PID {e.pid})", "medium",
                    [f"Log: {e.source}[{e.pid}] {e.message}", f"Processo: {label(p)}"],
                    "O PID do log aponta para um processo cujo nome não coincide com a origem do log.",
                    "Reuso de PID entre execução e snapshot, mascaramento de processo ou diferença de captura.",
                    ["Tempo de vida do PID (starttime em /proc)", "Mais eventos do mesmo PID"], [], "processo + log",
                    {"pids": [e.pid]}))
            am = re.search(r"(Accepted|Failed) \S+ for (\S+)", e.message)
            if am:
                link += f" | login de '{am.group(2)}' " + ("coincide" if am.group(2) == p.user else "difere") + " do usuário do processo"
        elif e.pid:
            link = f"(PID {e.pid} ausente do snapshot)"
        interesting = bool(INTEREST.search(e.message))
        if interesting:
            findings.append(Finding("Evento de log de interesse", "low", [f"{e.ts:%b %d %H:%M:%S} {e.source}: {e.message}"],
                "Evento tipicamente associado a falha de autenticação, sudo ou crash.",
                "Pode ser atividade normal ou tentativa de acesso.", ["Frequência/contexto dos eventos vizinhos"], [], "log",
                {"pids": [e.pid] if e.pid in by_pid else []}))
        if show_all_logs or linked or interesting:
            rows.append((e.ts, "LOG ", f"{e.source}[{e.pid}] {e.message}", link))
    rows.sort(key=lambda r: (r[0], r[1]))
    return rows, findings
