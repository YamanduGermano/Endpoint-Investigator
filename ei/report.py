"""Relatório textual (terminal/arquivo) e exportação JSON dos findings."""
from __future__ import annotations
import json, textwrap
from dataclasses import asdict
from datetime import datetime
from .models import SEV_ORDER
from .utils import label, unprivileged_write_reasons

W = 100
LIMITATIONS = [
    "Snapshot único: sem histórico; não há detecção de comportamento ao longo do tempo.",
    "O vínculo serviço<->arquivo é heurístico (caminhos em EXECSTART/cmd e casamento por nome) e pode gerar falsos positivos/negativos.",
    "Sem ACLs, capabilities, SUID/SGID, atributos imutáveis, crontabs, units systemd completas ou rede.",
    "Arquivos sem metadados de permissão não são avaliados (aparecem como 'sem metadados').",
    "Ausência de evento no log não prova ausência de atividade; logs curtos limitam a reconstrução temporal.",
    "Severidade é priorização para o analista, não veredito de comprometimento.",
]


def _wrap(prefix, text, ind="    "):
    return textwrap.fill(f"{prefix}{text}", W, subsequent_indent=ind + "  ")


def render_report(snap, an) -> str:
    m = snap.meta
    L = ["=" * W, "ENDPOINT INVESTIGATOR - relatório de investigação (snapshot)", "=" * W,
         f"Modo: {snap.mode} | origem: {snap.source}",
         f"Dataset: {m.get('dataset_type', '?')} | nível={m.get('level', '?')} | cenário={m.get('scenario', '?')}",
         f"Análise em: {datetime.now():%Y-%m-%d %H:%M:%S} | processos={len(snap.processes)} serviços={len(snap.services)} "
         f"arquivos={len(snap.perms)} eventos de log={len(snap.events)}"]
    for w in snap.warnings:
        L.append(f"[aviso] {w}")
    L += ["", "## 1. MAPA SERVIÇO -> PROCESSO -> RECURSOS", "-" * W]
    if not an.smap:
        L.append("(nenhum serviço coletado)")
    for e in an.smap:
        s = e["svc"]
        L.append(f"{s.unit} [{s.active}] user={s.user} EXECSTART={s.execstart}")
        for p, why in e["procs"]:
            L.append(f"    proc {label(p)}  ({why})")
        if not e["procs"]:
            L.append("    (nenhum processo associado no snapshot)")
        for path, srcs in e["files"].items():
            mt = snap.perms.get(path)
            if not mt:
                st = "sem metadados"
            else:
                r = unprivileged_write_reasons(mt)
                st = "PERMISSIVO: " + "; ".join(r) if r else f"ok ({mt.owner}:{mt.group} {mt.mode & 0o7777:04o})"
            L.append(f"    recurso {path}  [{', '.join(sorted(srcs))}] -> {st}")
    L += ["", "## 2. FINDINGS", "-" * W]
    if not an.findings:
        L.append("Nenhum finding: evidências insuficientes para qualquer conclusão.")
    for f in an.findings:
        L += [f"[{f.id}] {f.title}   <{f.severity.upper()}>", f"    Correlação: {f.correlation}", "    EVIDÊNCIA:"]
        L += [_wrap("      - ", x, "      ") for x in f.evidence]
        L.append(_wrap("    INTERPRETAÇÃO: ", f.interpretation))
        L.append(_wrap("    HIPÓTESE: ", f.hypothesis))
        if f.against:
            L.append("    CONTRA-EVIDÊNCIA:"); L += [_wrap("      - ", x, "      ") for x in f.against]
        L.append("    EVIDÊNCIA AUSENTE:"); L += [_wrap("      - ", x, "      ") for x in f.missing]
        L.append("")
    L += ["## 3. LINHA DO TEMPO (processo + serviço + log)", "-" * W]
    for ts, kind, text, link in an.timeline:
        L.append(f"{ts:%m-%d %H:%M:%S} {kind} {text} {link}".rstrip())
    L += ["", "## 4. RESUMO"]
    cnt: dict = {}
    for f in an.findings:
        cnt[f.severity] = cnt.get(f.severity, 0) + 1
    L.append(", ".join(f"{k}={cnt[k]}" for k in sorted(cnt, key=SEV_ORDER.get)) or "sem findings")
    L += ["", "## 5. LIMITAÇÕES / POSSÍVEIS FALSOS POSITIVOS", "-" * W] + [_wrap("- ", x, "") for x in LIMITATIONS]
    return "\n".join(L) + "\n"


def findings_json(an) -> str:
    return json.dumps([asdict(f) for f in an.findings], indent=2, ensure_ascii=False)
