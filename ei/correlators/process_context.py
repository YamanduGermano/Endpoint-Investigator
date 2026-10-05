"""C2: processo + PPID + usuário -> contexto de execução."""
from __future__ import annotations
import os, re
from ..models import Finding
from ..utils import USER_DIRS, ancestry, label, meta_str, unprivileged_write_reasons


def correlate_process_context(procs, by_pid, perms, events, svc_pids) -> list:
    out = []
    for p in procs:
        target = p.script if p.script else p.exe
        flags, sev = [], "info"
        in_user_dir = target.startswith(USER_DIRS)
        if in_user_dir:
            flags.append(f"executa recurso em diretório de usuário ({target})")
        parent = by_pid.get(p.ppid)
        if p.user == "root" and parent and parent.user != "root":
            flags.append(f"processo root filho de processo não-root ({label(parent)})"); sev = "medium"
        m = perms.get(target) if target.startswith("/") else None
        if p.user == "root" and m and unprivileged_write_reasons(m):
            flags.append("root executa recurso modificável por não-privilegiado: " + "; ".join(unprivileged_write_reasons(m)))
            sev = "medium"
        if not flags:
            continue
        chain = ancestry(p, by_pid)
        ev = [f"PID {p.pid} PPID {p.ppid} user={p.user} stat={p.stat} cmd='{p.cmd}'",
              "Cadeia: " + " -> ".join(label(c) for c in chain)] + [f"Indicador: {f}" for f in flags]
        if m:
            ev.append("Metadados do recurso: " + meta_str(m))
        against = []
        if p.pid not in svc_pids:
            ev.append("Processo não associado a nenhum serviço coletado")
        if p.user != "root":
            against.append(f"executa como '{p.user}' (sem privilégio elevado): impacto limitado a essa identidade")
        if m and m.owner == p.user and not unprivileged_write_reasons(m):
            against.append(f"dono do recurso ({m.owner}) coincide com o usuário do processo")
        if any(c.cmd.startswith("sshd") for c in chain):
            against.append("origem em sessão SSH de login (cadeia sshd -> shell)")
        for e in events:
            if e.pid == p.pid:
                ev.append(f"Log: {e.ts:%b %d %H:%M:%S} {e.source}[{e.pid}] {e.message}")
                if re.search(r"status=OK|completed", e.message):
                    against.append("log do próprio PID indica execução rotineira concluída com sucesso")
        twins = [q for q in perms if q != target and os.path.basename(q) == os.path.basename(target)] if target else []
        if twins:
            ev.append(f"Outro arquivo com o mesmo nome: {', '.join(twins)} (o processo usa {target}); não confundir por nome")
        out.append(Finding(
            f"Contexto de execução: PID {p.pid} ({os.path.basename(target)})", sev, ev,
            "Origem, identidade e cadeia de pais do processo descrevem como/por quem foi executado.",
            "Execução de script pessoal do usuário em sessão interativa (benigno provável)." if sev == "info"
            else "Possível uso indevido/elevação de privilégio; requer confirmação.",
            ["Conteúdo e hash do script", "Histórico de comandos do usuário / auditd execve"]
            + (["Se o diretório do usuário é confiável nesse host"] if in_user_dir else []),
            against, "processo + PPID + usuário (+ log)",
            {"pids": [p.pid], "files": [target] if target.startswith("/") else []}))
    return out
