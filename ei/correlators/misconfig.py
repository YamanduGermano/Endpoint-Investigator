"""Configurações inadequadas SEM vínculo com contexto privilegiado -> inconclusivo."""
from __future__ import annotations
from ..models import Finding
from ..utils import SENSITIVE, SYSTEM_DIRS, paths_in, meta_str, unprivileged_write_reasons


def flag_misconfig_without_link(perms, smap, procs, services) -> list:
    referenced = set()
    for e in smap:
        referenced |= set(e["files"])
    for p in procs:
        referenced |= set(paths_in(p.cmd)) | ({p.script} if p.script else set())
    has_cron = any("cron" in s.name for s in services if s.user == "root")
    out = []
    for path, m in perms.items():
        used = path in referenced or any(r.startswith(path.rstrip("/") + "/") for r in referenced)
        if path in SENSITIVE and m.mode & 0o007:
            out.append(Finding(f"Arquivo sensível acessível a 'others': {path}", "high", [meta_str(m)],
                "Arquivo de credenciais/privilégios com permissão para qualquer usuário.",
                "Exposição de hashes ou alteração de regras de privilégio.", ["Quem acessou o arquivo (auditd)"], [],
                "permissão", {"files": [path]}))
            continue
        sticky_dir = m.mode & 0o1000 and m.type == "directory"
        ww = bool(m.mode & 0o002) and not sticky_dir
        sysown = m.path.startswith(SYSTEM_DIRS) and m.owner != "root"
        if not (ww or sysown) or used:
            continue
        ev = [meta_str(m)] + [f"Permissão: {w}" for w in unprivileged_write_reasons(m)]
        ev.append("Nenhum serviço/processo do snapshot referencia este caminho")
        miss = ["Vínculo com execução privilegiada (unit, cron, sudoers, timers)", "Evidência de modificação (auditd/hash)"]
        if has_cron:
            miss.insert(0, "crontabs do root e /etc/cron.* (cron.service roda como root, mas crontabs não foram analisados)")
        out.append(Finding(f"Configuração permissiva sem vínculo observado: {path}", "inconclusive", ev,
            "Configuração inadequada (modificável por não-privilegiados), sem evidência de uso por contexto privilegiado.",
            "Se algum job/serviço privilegiado executar este arquivo, haveria risco de escalonamento; não há evidência disso.",
            miss, ["Não há processo, serviço ou log ligado ao arquivo"], "permissão x serviços x processos", {"files": [path]}))
    return out
