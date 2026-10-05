#!/usr/bin/env python3
"""Endpoint Investigator - prototipo (arquivo unico, so biblioteca padrao).

Fluxo: COLETA -> NORMALIZACAO -> CORRELACAO -> EVIDENCIAS -> HIPOTESES -> RESULTADO
Uso:   python3 investigator.py --data data/ --out out/report.txt [--json out/report.json]
"""
from __future__ import annotations
import argparse, csv, json, os, re, textwrap
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

# ----------------------------------------------------------------- modelos
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

@dataclass
class LogEvent:
    ts: datetime; host: str; source: str; pid: int | None; message: str

@dataclass
class Finding:
    title: str
    severity: str                     # high|medium|low|info|inconclusive
    evidence: list
    interpretation: str
    hypothesis: str
    missing: list
    against: list = field(default_factory=list)   # contra-evidencias
    correlation: str = ""
    id: str = ""

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "inconclusive": 4}
INTERP = re.compile(r"^(python[\d.]*|bash|sh|dash|perl|ruby|node)$")
USER_DIRS = ("/home/", "/tmp/", "/var/tmp/", "/dev/shm/")
SYSTEM_DIRS = ("/usr/", "/etc/", "/opt/", "/bin/", "/sbin/")
SENSITIVE = ("/etc/shadow", "/etc/sudoers", "/etc/gshadow")
LIMITATIONS = [
    "Snapshot unico: sem historico; nao ha deteccao de comportamento ao longo do tempo.",
    "services.txt nao lista arquivos usados pelo servico; o vinculo servico<->arquivo e heuristico "
    "(caminhos em EXECSTART/cmd e casamento por nome) e pode gerar falsos positivos/negativos.",
    "Sem ACLs, capabilities, SUID/SGID, atributos imutaveis, crontabs, units systemd completas ou rede.",
    "Arquivos sem metadados em permissions.csv nao sao avaliados (aparecem como 'sem metadados').",
    "Ausencia de evento no log nao prova ausencia de atividade; logs curtos limitam a reconstrucao temporal.",
    "Severidade e uma priorizacao para o analista, nao um veredito de comprometimento.",
]

# ----------------------------------------------------------- coleta / parse
def split_cmd(cmd: str):
    toks = cmd.split()
    exe = toks[0] if toks else ""
    args = toks[1:]
    script = ""
    if INTERP.match(os.path.basename(exe)):
        script = next((a for a in args if not a.startswith("-")), "")
    return exe, args, script

def naive(dt: datetime) -> datetime:
    return dt.replace(tzinfo=None)

def load_metadata(path):
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}

def load_processes(path) -> list[Process]:
    out = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            exe, args, script = split_cmd(r["cmd"])
            out.append(Process(naive(datetime.fromisoformat(r["timestamp"])), int(r["pid"]),
                               int(r["ppid"]), r["user"], r["stat"], r["cmd"], exe, args, script))
    return out

def load_permissions(path) -> dict[str, FileMeta]:
    out = {}
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            out[r["path"]] = FileMeta(r["path"], r["type"], r["owner"], r["group"],
                                      int(r["mode"], 8), naive(datetime.fromisoformat(r["mtime"])))
    return out

def load_services(path) -> list[Service]:
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

LOG_RE = re.compile(r"^(\w{3})\s+(\d+)\s+(\d\d:\d\d:\d\d)\s+(\S+)\s+([^\[:]+)(?:\[(\d+)\])?:\s*(.*)$")

def load_journal(path, year: int) -> list[LogEvent]:
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        m = LOG_RE.match(line)
        if not m:
            continue
        mon, day, t, host, src, pid, msg = m.groups()
        ts = datetime.strptime(f"{year} {mon} {day} {t}", "%Y %b %d %H:%M:%S")
        out.append(LogEvent(ts, host, src.strip(), int(pid) if pid else None, msg))
    return out

# --------------------------------------------------------------- utilitarios
def label(p: Process) -> str:
    return f"{p.pid}:{p.cmd[:32]}({p.user})"

def build_process_tree(procs):
    by_pid = {p.pid: p for p in procs}
    kids = {}
    for p in procs:
        kids.setdefault(p.ppid, []).append(p)
    return by_pid, kids

def ancestry(p: Process, by_pid) -> list[Process]:
    chain, seen = [p], {p.pid}
    while chain[-1].ppid in by_pid and chain[-1].ppid not in seen:
        nxt = by_pid[chain[-1].ppid]; chain.append(nxt); seen.add(nxt.pid)
    return list(reversed(chain))

def descendants(p: Process, kids) -> list[Process]:
    out, stack = [], list(kids.get(p.pid, []))
    while stack:
        c = stack.pop(); out.append(c); stack.extend(kids.get(c.pid, []))
    return out

def paths_in(text: str) -> list[str]:
    return re.findall(r"(?<![\w.@-])(/[\w./-]+)", text)

def unprivileged_write_reasons(m: FileMeta) -> list[str]:
    """Por que um usuario nao privilegiado poderia modificar este recurso?"""
    r = []
    sticky = bool(m.mode & 0o1000) and m.type == "directory"
    if m.mode & 0o002 and not sticky:
        r.append(f"world-writable (o+w, modo {m.mode:04o})")
    if m.mode & 0o020 and m.group != "root":
        r.append(f"gravavel pelo grupo '{m.group}' (g+w)")
    if m.owner != "root":
        r.append(f"dono e '{m.owner}' (nao privilegiado)")
    return r

def meta_str(m: FileMeta) -> str:
    return f"{m.path} {m.type} {m.owner}:{m.group} modo={m.mode:04o} mtime={m.mtime:%Y-%m-%d %H:%M:%S}"

# ---------------------------------------------------- servico <-> processo
def match_service_to_process(svc: Service, procs) -> list[tuple[Process, str]]:
    """Seeds: processos com executavel em caminho absoluto casando com a unit."""
    res = []
    sexe, sargs, sscript = split_cmd(svc.execstart)
    if INTERP.match(os.path.basename(sexe)) and sscript:   # servico = interpretador + script
        return [(p, "cmd igual ao EXECSTART (interpretador + script)") for p in procs
                if p.exe == sexe and p.script == sscript]
    for p in procs:
        if not p.exe.startswith("/"):
            continue
        pb = os.path.basename(p.exe)
        if p.exe == svc.exe:
            res.append((p, "executavel igual ao EXECSTART"))
        elif pb == os.path.basename(svc.exe) or pb == svc.name:
            res.append((p, "nome do executavel == nome do EXECSTART/unit (heuristica)"))
        elif svc.name in pb:
            res.append((p, f"nome da unit '{svc.name}' contido em '{pb}' (heuristica)"))
    return res

def build_service_map(services, procs, kids):
    smap = []
    for s in services:
        seeds = match_service_to_process(s, procs)
        sp = {p.pid: (p, why) for p, why in seeds}
        for p, _ in seeds:                       # descendentes com a MESMA identidade
            for d in descendants(p, kids):
                if d.user == p.user and d.pid not in sp:
                    sp[d.pid] = (d, "descendente do processo do servico, mesmo usuario")
        files = {}
        for pth in paths_in(s.execstart):
            files.setdefault(pth, set()).add("EXECSTART")
        for p, _ in sp.values():
            for pth in paths_in(p.cmd) + ([p.script] if p.script.startswith("/") else []):
                files.setdefault(pth, set()).add(f"cmd do PID {p.pid}")
        smap.append({"svc": s, "procs": list(sp.values()), "files": files})
    return smap

# -------------------------------------------------------------- correlacoes
def correlate_service_file_privilege(smap, perms) -> list[Finding]:
    """C1: servico + arquivo + usuario -> relacao de privilegio."""
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
            ev = [f"Servico {s.unit} declarado como user={s.user}, EXECSTART='{s.execstart}'",
                  f"Recurso referenciado ({', '.join(sorted(srcs))}): {meta_str(m)}"]
            ev += [f"Recurso: {r}" for r in reasons]
            if preasons:
                ev.append(f"Diretorio pai {parent.path} ({parent.owner}:{parent.group} {parent.mode:04o}): "
                          + "; ".join(preasons))
            sev, against = "medium", []
            if starts and m.mtime > min(starts):
                ev.append(f"mtime do recurso ({m.mtime}) e posterior ao processo do servico ({min(starts)})")
                sev = "high"
            elif starts:
                against.append("mtime do recurso anterior ao inicio do servico: sem sinal de alteracao posterior")
            out.append(Finding(
                f"Servico root usa recurso modificavel por nao-privilegiado: {path}", sev, ev,
                "Combinacao identidade privilegiada + recurso usado + capacidade de escrita = "
                "possivel relacao de privilegio insegura.",
                "Um usuario nao privilegiado poderia alterar o recurso e ter codigo executado como root. "
                "Isso NAO prova exploracao.",
                ["Conteudo/hash do recurso e baseline conhecido", "Log de auditoria de escrita (auditd) no recurso",
                 "Quais usuarios reais pertencem ao grupo/dono com escrita"], against,
                "servico + arquivo + usuario (+ mtime)"))
    return out

def correlate_identity_mismatch(smap) -> list[Finding]:
    out = []
    for e in smap:
        s = e["svc"]; seeds = [(p, w) for p, w in e["procs"] if "descendente" not in w]
        if seeds and all(p.user != s.user for p, _ in seeds):
            users = sorted({p.user for p, _ in seeds})
            out.append(Finding(
                f"Identidade declarada diverge da observada em {s.unit}", "info",
                [f"services.txt: {s.unit} user={s.user}", "Processos associados: " + "; ".join(label(p) for p, _ in seeds)],
                f"O servico consta como '{s.user}' mas o(s) processo(s) principal(is) roda(m) como {users}.",
                "Reducao de privilegio (ex.: Apache descartando root) ou coluna USER reflete apenas o gerenciador; "
                "alternativamente, associacao heuristica incorreta.",
                ["Unit file (User=/Group=)", f"/proc/<pid>/status (UIDs reais/efetivos)", "Portas escutadas (ss -tulpn)"],
                [f"PID {p.pid} e filho direto de PID 1 (gerenciador de servicos)" for p, w in seeds if p.ppid == 1][:1],
                "servico + processo + usuario"))
    return out

def correlate_process_context(procs, by_pid, perms, events, svc_pids) -> list[Finding]:
    """C2: processo + PPID + usuario -> contexto de execucao."""
    out = []
    for p in procs:
        target = p.script if p.script else p.exe
        flags, sev = [], "info"
        in_user_dir = target.startswith(USER_DIRS)
        if in_user_dir:
            flags.append(f"executa recurso em diretorio de usuario ({target})")
        parent = by_pid.get(p.ppid)
        if p.user == "root" and parent and parent.user != "root":
            flags.append(f"processo root filho de processo nao-root ({label(parent)})")
            sev = "medium"
        m = perms.get(target) if target.startswith("/") else None
        if p.user == "root" and m and unprivileged_write_reasons(m):
            flags.append("root executa recurso modificavel por nao-privilegiado: " + "; ".join(unprivileged_write_reasons(m)))
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
            ev.append("Processo nao associado a nenhum servico listado")
        if p.user != "root":
            against.append(f"executa como '{p.user}' (sem privilegio elevado): impacto limitado a essa identidade")
        if m and m.owner == p.user and not unprivileged_write_reasons(m):
            against.append(f"dono do recurso ({m.owner}) coincide com o usuario do processo")
        if any(c.cmd.startswith("sshd") for c in chain):
            against.append("origem em sessao SSH legitima de login (cadeia sshd -> shell)")
        for e in events:
            if e.pid == p.pid:
                ev.append(f"Log: {e.ts:%b %d %H:%M:%S} {e.source}[{e.pid}] {e.message}")
                if re.search(r"status=OK|completed", e.message):
                    against.append("log do proprio PID indica execucao rotineira concluida com sucesso")
        twins = [q for q in perms if q != target and os.path.basename(q) == os.path.basename(target)] if target else []
        if twins:
            ev.append(f"Outro arquivo com o mesmo nome: {', '.join(twins)} (o processo usa {target}); nao confundir por nome")
        out.append(Finding(
            f"Contexto de execucao: PID {p.pid} ({os.path.basename(target)})", sev, ev,
            "Origem, identidade e cadeia de pais do processo descrevem como/por quem foi executado.",
            "Execucao de script pessoal do usuario em sessao interativa (benigno provavel)" if sev == "info"
            else "Possivel elevacao/uso indevido de privilegio; requer confirmacao.",
            ["Conteudo e hash do script", "Historico de comandos do usuario / auditd execve"]
            + (["Se /home/<user> e confiavel nesse host"] if in_user_dir else []), against, "processo + PPID + usuario (+ log)"))
    return out

def correlate_timeline(procs, services, events, by_pid):
    """C3: processo + servico + log -> linha do tempo e consistencia."""
    rows, findings = [], []
    for p in procs:
        rows.append((p.ts, "PROC", f"{label(p)} ppid={p.ppid}", ""))
    for e in events:
        link = ""
        m = re.match(r"Started (\S+)", e.message)
        if m:
            u = next((s for s in services if s.unit == m.group(1)), None)
            if u:
                link = f"-> servico {u.unit} (user={u.user})"
        if e.pid and e.pid in by_pid:
            p = by_pid[e.pid]
            link = f"-> PID {p.pid} '{p.cmd[:30]}' user={p.user}"
            ln, pn = e.source, os.path.basename(p.exe).rstrip(":")
            names = {pn, os.path.basename(p.script)} if p.script else {pn}
            if pn == "init":                      # /sbin/init costuma ser link para o systemd
                names.add("systemd")
            if not any(ln in n or n in ln for n in names if n):
                findings.append(Finding(
                    f"Log e processo com mesmo PID mas nomes diferentes (PID {e.pid})", "medium",
                    [f"Log: {e.source}[{e.pid}] {e.message}", f"Processo: {label(p)}"],
                    "O PID do log aponta para um processo cujo nome nao coincide com a origem do log.",
                    "Reuso de PID entre snapshot e log, mascaramento de processo ou simples diferenca de captura.",
                    ["Tempo de vida do PID (starttime em /proc)", "Mais eventos do mesmo PID"], [],
                    "processo + log"))
            am = re.search(r"(Accepted|Failed) \S+ for (\S+)", e.message)
            if am:
                link += f" | login de '{am.group(2)}' " + ("coincide" if am.group(2) == p.user else "difere") + " com usuario do processo"
        elif e.pid:
            link = f"(PID {e.pid} ausente do snapshot)"
        rows.append((e.ts, "LOG ", f"{e.source}[{e.pid}] {e.message}", link))
        if re.search(r"Failed password|authentication failure|segfault|COMMAND=|session opened for user root", e.message):
            findings.append(Finding("Evento de log de interesse", "low", [f"{e.ts:%b %d %H:%M:%S} {e.source}: {e.message}"],
                "Evento tipicamente associado a autenticacao falha, sudo ou crash.",
                "Pode ser atividade normal ou tentativa de acesso.", ["Frequencia/contexto de eventos vizinhos"], [], "log"))
    rows.sort(key=lambda r: (r[0], r[1]))
    return rows, findings

def flag_misconfig_without_link(perms, smap, procs, services) -> list[Finding]:
    """Permissao inadequada SEM vinculo com servico/processo -> inconclusivo (nao e prova de exploracao)."""
    referenced = set()
    for e in smap:
        referenced |= set(e["files"])
    for p in procs:
        referenced |= set(paths_in(p.cmd))
    out = []
    has_cron = any("cron" in s.name for s in services if s.user == "root")
    for path, m in perms.items():
        used = path in referenced or any(r.startswith(path.rstrip("/") + "/") for r in referenced)
        if path in SENSITIVE and m.mode & 0o007:
            out.append(Finding(f"Arquivo sensivel acessivel a 'others': {path}", "high", [meta_str(m)],
                "Arquivo de credenciais/privilegios com permissao para qualquer usuario.",
                "Exposicao de hashes ou alteracao de regras de privilegio.", ["Quem acessou o arquivo (auditd)"], [], "permissao"))
            continue
        ww = m.mode & 0o002 and not (m.mode & 0o1000 and m.type == "directory")
        sysown = m.path.startswith(SYSTEM_DIRS) and m.owner != "root"
        if not (ww or sysown) or used:
            continue
        why = unprivileged_write_reasons(m)
        mentions = []
        ev = [meta_str(m)] + [f"Permissao: {w}" for w in why]
        ev.append("Nenhum servico/processo do snapshot referencia este caminho")
        miss = ["Vinculo com execucao privilegiada (unit, cron, sudoers, timers)", "Evidencia de modificacao (auditd/hash)"]
        if has_cron:
            miss.insert(0, "crontabs do root e /etc/cron.* (cron.service roda como root, mas crontabs nao foram coletados)")
        out.append(Finding(f"Configuracao permissiva sem vinculo observado: {path}", "inconclusive", ev,
            "Configuracao inadequada (arquivo gravavel por qualquer usuario), mas sem evidencia de uso por contexto privilegiado.",
            "Se algum job/servico privilegiado executar este arquivo, haveria risco de escalonamento; nao ha evidencia disso.",
            miss, ["Nao ha processo, servico ou log ligado ao arquivo"], "permissao x servicos x processos"))
    return out

# ----------------------------------------------------------------- relatorio
def render_report(meta, smap, perms, findings, timeline) -> str:
    W = 100
    def wrap(prefix, text, ind="    "):
        return textwrap.fill(f"{prefix}{text}", W, subsequent_indent=ind + "  ")
    L = ["=" * W, "ENDPOINT INVESTIGATOR - relatorio de investigacao (snapshot)", "=" * W,
         f"Dataset: {meta.get('dataset_type','?')} | nivel={meta.get('level','?')} | cenario={meta.get('scenario','?')}",
         f"Gerado em: {datetime.now():%Y-%m-%d %H:%M:%S}", ""]
    L += ["## 1. MAPA SERVICO -> PROCESSO -> RECURSOS", "-" * W]
    for e in smap:
        s = e["svc"]
        L.append(f"{s.unit} [{s.active}] user={s.user} EXECSTART={s.execstart}")
        for p, why in e["procs"]:
            L.append(f"    proc {label(p)}  ({why})")
        if not e["procs"]:
            L.append("    (nenhum processo associado no snapshot)")
        for path, srcs in e["files"].items():
            m = perms.get(path)
            st = "sem metadados" if not m else ("PERMISSIVO: " + "; ".join(unprivileged_write_reasons(m)) if unprivileged_write_reasons(m) else f"ok ({m.owner}:{m.group} {m.mode:04o})")
            L.append(f"    recurso {path}  [{', '.join(sorted(srcs))}] -> {st}")
    L += ["", "## 2. FINDINGS", "-" * W]
    if not findings:
        L.append("Nenhum finding gerado: evidencias insuficientes para qualquer conclusao.")
    for f in findings:
        L += [f"[{f.id}] {f.title}   <{f.severity.upper()}>", f"    Correlacao: {f.correlation}", "    EVIDENCIA:"]
        L += [wrap("      - ", x, "      ") for x in f.evidence]
        L.append(wrap("    INTERPRETACAO: ", f.interpretation))
        L.append(wrap("    HIPOTESE: ", f.hypothesis))
        if f.against:
            L.append("    CONTRA-EVIDENCIA:"); L += [wrap("      - ", x, "      ") for x in f.against]
        L.append("    EVIDENCIA AUSENTE:"); L += [wrap("      - ", x, "      ") for x in f.missing]
        L.append("")
    L += ["## 3. LINHA DO TEMPO (processo + servico + log)", "-" * W]
    for ts, kind, text, link in timeline:
        L.append(f"{ts:%m-%d %H:%M:%S} {kind} {text} {link}".rstrip())
    L += ["", "## 4. RESUMO"]
    cnt = {}
    for f in findings: cnt[f.severity] = cnt.get(f.severity, 0) + 1
    L.append(", ".join(f"{k}={cnt[k]}" for k in sorted(cnt, key=SEV_ORDER.get)) or "sem findings")
    L += ["", "## 5. LIMITACOES / POSSIVEIS FALSOS POSITIVOS", "-" * W] + [wrap("- ", x, "") for x in LIMITATIONS]
    return "\n".join(L) + "\n"

def main():
    ap = argparse.ArgumentParser(description="Endpoint Investigator (prototipo)")
    ap.add_argument("--data", default="./dataset"); ap.add_argument("--out", default="out/report.txt")
    ap.add_argument("--json", help="grava tambem findings em JSON")
    a = ap.parse_args()
    d = Path(a.data)
    meta = load_metadata(d / "metadata.json")
    year = int(str(meta.get("generated_at", datetime.now().isoformat()))[:4])
    procs = load_processes(d / "processes.csv"); perms = load_permissions(d / "permissions.csv")
    services = load_services(d / "services.txt"); events = load_journal(d / "journal.log", year)
    by_pid, kids = build_process_tree(procs)
    smap = build_service_map(services, procs, kids)
    svc_pids = {p.pid for e in smap for p, _ in e["procs"]}

    findings = []
    findings += correlate_service_file_privilege(smap, perms)
    findings += correlate_identity_mismatch(smap)
    findings += correlate_process_context(procs, by_pid, perms, events, svc_pids)
    findings += flag_misconfig_without_link(perms, smap, procs, services)
    timeline, tl_findings = correlate_timeline(procs, services, events, by_pid)
    findings += tl_findings
    findings.sort(key=lambda f: SEV_ORDER[f.severity])
    for i, f in enumerate(findings, 1): f.id = f"F-{i:03d}"

    report = render_report(meta, smap, perms, findings, timeline)
    print(report)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True); Path(a.out).write_text(report, encoding="utf-8")
    if a.json:
        Path(a.json).write_text(json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False), encoding="utf-8")

if __name__ == "__main__":
    main()