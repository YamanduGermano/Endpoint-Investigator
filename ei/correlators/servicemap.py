"""Base das correlações: associa serviço -> processos -> recursos referenciados."""
from __future__ import annotations
import os
from ..utils import split_cmd, paths_in, descendants, INTERP


def match_service_to_process(svc, procs) -> list:
    """Retorna [(processo, motivo)] — processos 'semente' do serviço."""
    if svc.main_pid:
        m = [(p, "MainPID informado pelo systemd") for p in procs if p.pid == svc.main_pid]
        if m:
            return m
    sexe, _, sscript = split_cmd(svc.execstart)
    if INTERP.match(os.path.basename(sexe)) and sscript:       # serviço = interpretador + script
        return [(p, "cmd igual ao EXECSTART (interpretador + script)") for p in procs
                if INTERP.match(os.path.basename(p.exe)) and p.script == sscript]
    res = []
    for p in procs:
        if not p.exe.startswith("/"):
            continue
        pb = os.path.basename(p.exe)
        if p.exe == svc.exe:
            res.append((p, "executável igual ao EXECSTART"))
        elif pb == os.path.basename(svc.exe) or pb == svc.name:
            res.append((p, "nome do executável == EXECSTART/unit (heurística)"))
        elif svc.name in pb:
            res.append((p, f"nome da unit '{svc.name}' contido em '{pb}' (heurística)"))
    return res


def build_service_map(services, procs, kids) -> list:
    """[{svc, procs:[(Process, motivo)], files:{path:{origens}}}]"""
    smap = []
    for s in services:
        seeds = match_service_to_process(s, procs)
        sp = {p.pid: (p, why) for p, why in seeds}
        for p, _ in seeds:                      # descendentes com a MESMA identidade
            for d in descendants(p, kids):
                if d.user == p.user and d.pid not in sp:
                    sp[d.pid] = (d, "descendente do processo do serviço, mesmo usuário")
        files: dict = {}
        for pth in paths_in(s.execstart):
            files.setdefault(pth, set()).add("EXECSTART")
        for p, _ in sp.values():
            for pth in paths_in(p.cmd) + ([p.script] if p.script.startswith("/") else []):
                files.setdefault(pth, set()).add(f"cmd do PID {p.pid}")
        smap.append({"svc": s, "procs": list(sp.values()), "files": files})
    return smap
