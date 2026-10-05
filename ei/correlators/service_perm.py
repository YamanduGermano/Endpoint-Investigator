"""C1: serviço + arquivo + usuário -> relação de privilégio (e divergência de identidade)."""
from __future__ import annotations
import os
from ..models import Finding
from ..utils import unprivileged_write_reasons, meta_str, label


def correlate_service_file_privilege(smap, perms) -> list:
    out = []
    for e in smap:
        s = e["svc"]
        if s.user != "root":
            continue
        starts = [p.ts for p, _ in e["procs"]]
        for path, srcs in e["files"].items():
            m = perms.get(path)
            if not m:
                continue
            reasons = unprivileged_write_reasons(m)
            parent = perms.get(os.path.dirname(path))
            preasons = unprivileged_write_reasons(parent) if parent else []
            if not reasons and not preasons:
                continue
            ev = [f"Serviço {s.unit} declarado user={s.user}, EXECSTART='{s.execstart}'",
                  f"Recurso referenciado ({', '.join(sorted(srcs))}): {meta_str(m)}"]
            ev += [f"Recurso: {r}" for r in reasons]
            if preasons:
                ev.append(f"Diretório pai {parent.path} ({parent.owner}:{parent.group} {parent.mode & 0o7777:04o}): " + "; ".join(preasons))
            sev, against = "medium", []
            if starts and m.mtime > min(starts):
                ev.append(f"mtime do recurso ({m.mtime}) é posterior ao processo do serviço ({min(starts)})")
                sev = "high"
            elif starts:
                against.append("mtime do recurso anterior ao início do serviço: sem sinal de alteração posterior")
            out.append(Finding(
                f"Serviço root usa recurso modificável por não-privilegiado: {path}", sev, ev,
                "Identidade privilegiada + recurso usado + capacidade de escrita = possível relação de privilégio insegura.",
                "Um usuário não privilegiado poderia alterar o recurso e ter código executado como root. Isso NÃO prova exploração.",
                ["Conteúdo/hash do recurso e baseline conhecido", "Log de auditoria de escrita (auditd) no recurso",
                 "Quais usuários reais pertencem ao grupo/dono com escrita"], against, "serviço + arquivo + usuário (+ mtime)",
                {"services": [s.unit], "files": [path], "pids": [p.pid for p, _ in e["procs"]]}))
    return out


def correlate_identity_mismatch(smap) -> list:
    out = []
    for e in smap:
        s = e["svc"]
        seeds = [(p, w) for p, w in e["procs"] if "descendente" not in w]
        if seeds and all(p.user != s.user for p, _ in seeds):
            users = sorted({p.user for p, _ in seeds})
            direct = [f"PID {p.pid} é filho direto de PID 1 (gerenciador de serviços)" for p, _ in seeds if p.ppid == 1][:1]
            out.append(Finding(
                f"Identidade declarada diverge da observada em {s.unit}", "info",
                [f"Serviço: {s.unit} user={s.user}", "Processos associados: " + "; ".join(label(p) for p, _ in seeds)],
                f"O serviço consta como '{s.user}', mas o(s) processo(s) principal(is) roda(m) como {users}.",
                "Redução de privilégio (ex.: servidor web descartando root), coluna USER refletindo só o gerenciador, "
                "ou associação heurística incorreta.",
                ["Unit file (User=/Group=)", "/proc/<pid>/status (UIDs real/efetivo)", "Portas escutadas (ss -tulpn)"], direct,
                "serviço + processo + usuário", {"services": [s.unit], "pids": [p.pid for p, _ in seeds]}))
    return out
