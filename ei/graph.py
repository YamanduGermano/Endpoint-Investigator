"""Mapeamento de relações entre objetos (serviços, processos, recursos, identidades, logs, findings).

Saídas: JSON estruturado (nós/arestas), Graphviz DOT e imagem SVG (sem dependências externas).
O SVG usa layout em colunas por tipo de objeto: Logs | Serviços | Processos | Recursos | Identidades.
"""
from __future__ import annotations
import json, os, re
from html import escape
from .models import SEV_ORDER
from .utils import ancestry, unprivileged_write_reasons

COLS = ["log", "service", "process", "file", "identity"]
TITLES = {"log": "Eventos de log", "service": "Serviços", "process": "Processos", "file": "Recursos (arquivos)", "identity": "Identidades"}
FILL = {"log": "#f3e8ff", "service": "#dbeafe", "process": "#dcfce7", "file": "#fef9c3", "identity": "#fee2e2"}
SEVCOL = {"high": "#dc2626", "medium": "#ea580c", "low": "#ca8a04", "info": "#2563eb", "inconclusive": "#6b7280"}
EDGE = {  # rel: (cor, tracejado)
    "runs": ("#16a34a", ""), "child_of": ("#64748b", ""), "executes": ("#0891b2", ""), "uses": ("#2563eb", ""),
    "runs_as": ("#9333ea", "4 3"), "declared_as": ("#9333ea", "1 3"), "owned_by": ("#a16207", "4 3"),
    "writable_by": ("#dc2626", "6 3"), "log_of": ("#a855f7", "2 2"), "started": ("#a855f7", ""),
}
EDGE_TXT = {"runs": "serviço roda processo", "child_of": "filho de (PPID)", "executes": "executa arquivo", "uses": "serviço usa arquivo",
            "runs_as": "processo roda como", "declared_as": "usuário declarado", "owned_by": "dono do arquivo",
            "writable_by": "gravável por (risco)", "log_of": "log sobre PID", "started": "log: serviço iniciado"}


def build_graph(snap, an, full: bool = False) -> dict:
    nodes, edges = {}, set()
    sev_of, tags = {}, {}

    def tag(nid, f):
        tags.setdefault(nid, []).append(f.id)
        if nid not in sev_of or SEV_ORDER[f.severity] < SEV_ORDER[sev_of[nid]]:
            sev_of[nid] = f.severity

    for f in an.findings:
        for u in f.refs.get("services", []): tag(f"svc:{u}", f)
        for p in f.refs.get("pids", []): tag(f"proc:{p}", f)
        for x in f.refs.get("files", []): tag(f"file:{x}", f)

    def add(nid, typ, lab, sub=""):
        nodes.setdefault(nid, {"id": nid, "type": typ, "label": lab, "sub": sub})
        return nid

    def user(name):  return add(f"user:{name}", "identity", name, "usuário")
    def edge(a, b, rel): edges.add((a, b, rel))

    svc_pids = {p.pid for e in an.smap for p, _ in e["procs"]}
    log_pids = {e.pid for e in snap.events if e.pid in an.by_pid}
    base = set(an.by_pid) if full else (svc_pids | {pid for f in an.findings for pid in f.refs.get("pids", [])} | log_pids)
    include = set(base)
    for pid in base:
        include |= {c.pid for c in ancestry(an.by_pid[pid], an.by_pid)} if pid in an.by_pid else set()

    def add_file(path):
        m = snap.perms.get(path)
        nid = add(f"file:{path}", "file", path, f"{m.owner}:{m.group} {m.mode & 0o7777:04o}" if m else "sem metadados")
        if m:
            edge(nid, user(m.owner), "owned_by")
            if m.mode & 0o002 and not (m.mode & 0o1000 and m.type == "directory"):
                edge(nid, add("ident:others", "identity", "qualquer usuário (others)", "o+w"), "writable_by")
            if m.mode & 0o020 and m.group != "root":
                edge(nid, add(f"group:{m.group}", "identity", f"grupo {m.group}", "g+w"), "writable_by")
        return nid

    for e in an.smap:
        s = e["svc"]
        sid = add(f"svc:{s.unit}", "service", s.unit, f"user={s.user}")
        edge(sid, user(s.user), "declared_as")
        for p, _ in e["procs"]:
            if p.pid in include:
                edge(sid, f"proc:{p.pid}", "runs")
        for path in e["files"]:
            edge(sid, add_file(path), "uses")
    for pid in sorted(include):
        p = an.by_pid.get(pid)
        if not p:
            continue
        add(f"proc:{pid}", "process", f"{pid} {os.path.basename(p.exe.rstrip(':')) or p.cmd[:20]}", f"{p.user} · ppid {p.ppid}")
        edge(f"proc:{pid}", user(p.user), "runs_as")
        if p.ppid in include and p.ppid in an.by_pid:
            edge(f"proc:{pid}", f"proc:{p.ppid}", "child_of")
        if pid in base:
            tgt = p.script or p.exe
            if tgt.startswith("/"):
                edge(f"proc:{pid}", add_file(tgt), "executes")
    for f in an.findings:
        for x in f.refs.get("files", []):
            add_file(x)
    for i, ev in enumerate(snap.events):
        lid = None
        if ev.pid in include:
            lid = add(f"log:{i}", "log", f"{ev.ts:%H:%M:%S} {ev.source}[{ev.pid}]", ev.message[:34])
            edge(lid, f"proc:{ev.pid}", "log_of")
        mm = re.match(r"Started (\S+)", ev.message)
        if mm and f"svc:{mm.group(1)}" in nodes:
            lid = lid or add(f"log:{i}", "log", f"{ev.ts:%H:%M:%S} {ev.source}", ev.message[:34])
            edge(lid, f"svc:{mm.group(1)}", "started")
    for nid, n in nodes.items():
        n["severity"] = sev_of.get(nid, "")
        n["findings"] = tags.get(nid, [])
    return {"meta": {"mode": snap.mode, "source": snap.source, "full": full},
            "nodes": list(nodes.values()),
            "edges": [{"source": a, "target": b, "relation": r} for a, b, r in sorted(edges)],
            "findings": [{"id": f.id, "severity": f.severity, "title": f.title} for f in an.findings]}


# ------------------------------------------------------------------ exportadores
def to_json(g) -> str:
    return json.dumps(g, indent=2, ensure_ascii=False)


def to_dot(g) -> str:
    shape = {"log": "note", "service": "box3d", "process": "ellipse", "file": "box", "identity": "house"}
    L = ["digraph endpoint {", "  rankdir=LR; node [fontname=Helvetica,fontsize=10,style=filled];"]
    for n in g["nodes"]:
        col = SEVCOL.get(n["severity"], "#334155")
        lab = (n["label"] + "\\n" + n["sub"]).replace('"', "'")
        L.append(f'  "{n["id"]}" [label="{lab}",shape={shape[n["type"]]},fillcolor="{FILL[n["type"]]}",color="{col}",penwidth={3 if n["severity"] else 1}];')
    for e in g["edges"]:
        c, d = EDGE[e["relation"]]
        L.append(f'  "{e["source"]}" -> "{e["target"]}" [label="{e["relation"]}",color="{c}",fontsize=8{",style=dashed" if d else ""}];')
    return "\n".join(L + ["}"]) + "\n"


def _cut(s, n):
    s = str(s)
    return s if len(s) <= n else "…" + s[-(n - 1):] if s.startswith("/") else s[:n - 1] + "…"


def to_svg(g) -> str:
    NW, NH, GAPX, ROW, TOP, PAD = 214, 40, 150, 56, 70, 30
    cols = {c: [n for n in g["nodes"] if n["type"] == c] for c in COLS}
    used = [c for c in COLS if cols[c]]
    for c in cols:
        if c == "log":
            cols[c].sort(key=lambda n: n["label"])
        elif c == "process":
            cols[c].sort(key=lambda n: int(n["id"].split(":")[1]))
    xs = {c: PAD + i * (NW + GAPX) for i, c in enumerate(used)}
    pos = {}
    for c in used:
        for i, n in enumerate(cols[c]):
            pos[n["id"]] = (xs[c], TOP + i * ROW)
    nrows = max(len(cols[c]) for c in used) if used else 1
    used_rel = sorted({e["relation"] for e in g["edges"]})
    legend_y = TOP + nrows * ROW + 20
    fl = g["findings"]
    height = legend_y + 24 + 18 * (len(used_rel) + 2) // 2 + 22 * (len(fl) + 2)
    width = PAD * 2 + len(used) * NW + (len(used) - 1) * GAPX
    width = max(width, 760)
    S = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" font-family="Helvetica,Arial,sans-serif">',
         '<rect width="100%" height="100%" fill="#ffffff"/>',
         f'<text x="{PAD}" y="28" font-size="18" font-weight="bold" fill="#0f172a">Endpoint Investigator — mapa de relações ({escape(str(g["meta"]["mode"]))})</text>',
         f'<text x="{PAD}" y="46" font-size="11" fill="#475569">{escape(_cut(g["meta"]["source"], 120))} · borda colorida = severidade do finding · [F-xxx] = ids na legenda</text>',
         '<defs>' + "".join(f'<marker id="a_{r}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{EDGE[r][0]}"/></marker>' for r in EDGE) + '</defs>']
    for c in used:
        S.append(f'<text x="{xs[c] + NW / 2}" y="{TOP - 16}" text-anchor="middle" font-size="12" font-weight="bold" fill="#334155">{TITLES[c]}</text>')
    ctype = {n["id"]: n["type"] for n in g["nodes"]}
    for e in g["edges"]:
        a, b = e["source"], e["target"]
        if a not in pos or b not in pos:
            continue
        (xa, ya), (xb, yb) = pos[a], pos[b]
        ya += NH / 2; yb += NH / 2
        col, dash = EDGE[e["relation"]]
        if xa == xb:                                  # mesma coluna: laço à esquerda
            x = xa; d = f"M{x},{ya} C{x - 70},{ya} {x - 70},{yb} {x},{yb}"
        elif xa < xb:
            x1, x2 = xa + NW, xb; mx = (x1 + x2) / 2; d = f"M{x1},{ya} C{mx},{ya} {mx},{yb} {x2},{yb}"
        else:
            x1, x2 = xa, xb + NW; mx = (x1 + x2) / 2; d = f"M{x1},{ya} C{mx},{ya} {mx},{yb} {x2},{yb}"
        da = f' stroke-dasharray="{dash}"' if dash else ""
        S.append(f'<path d="{d}" fill="none" stroke="{col}" stroke-width="1.6" opacity="0.85"{da} marker-end="url(#a_{e["relation"]})"/>')
    for n in g["nodes"]:
        x, y = pos[n["id"]]
        sc = SEVCOL.get(n["severity"], "#64748b"); sw = 3 if n["severity"] else 1.2
        dash = ' stroke-dasharray="5 3"' if n["severity"] == "inconclusive" else ""
        S.append(f'<rect x="{x}" y="{y}" width="{NW}" height="{NH}" rx="8" fill="{FILL[n["type"]]}" stroke="{sc}" stroke-width="{sw}"{dash}/>')
        S.append(f'<text x="{x + 8}" y="{y + 16}" font-size="11.5" font-weight="bold" fill="#0f172a">{escape(_cut(n["label"], 30))}</text>')
        S.append(f'<text x="{x + 8}" y="{y + 31}" font-size="10" fill="#475569">{escape(_cut(n["sub"], 34))}</text>')
        if n["findings"]:
            S.append(f'<text x="{x + NW - 6}" y="{y - 3}" text-anchor="end" font-size="10" font-weight="bold" fill="{sc}">[{escape(",".join(n["findings"]))}]</text>')
    y = legend_y
    S.append(f'<text x="{PAD}" y="{y}" font-size="12" font-weight="bold" fill="#334155">Legenda de relações</text>')
    for i, r in enumerate(used_rel):
        cx = PAD + (i % 3) * 330; cy = y + 18 + (i // 3) * 18
        col, dash = EDGE[r]
        S.append(f'<line x1="{cx}" y1="{cy - 4}" x2="{cx + 34}" y2="{cy - 4}" stroke="{col}" stroke-width="2"' + (f' stroke-dasharray="{dash}"' if dash else "") + '/>')
        S.append(f'<text x="{cx + 42}" y="{cy}" font-size="10.5" fill="#334155">{escape(EDGE_TXT[r])}</text>')
    y += 18 + ((len(used_rel) + 2) // 3) * 18 + 18
    S.append(f'<text x="{PAD}" y="{y}" font-size="12" font-weight="bold" fill="#334155">Findings</text>')
    for i, f in enumerate(fl):
        S.append(f'<text x="{PAD}" y="{y + 18 + i * 17}" font-size="10.5" fill="{SEVCOL[f["severity"]]}">[{f["id"]}] {f["severity"].upper()} — {escape(_cut(f["title"], 130))}</text>')
    S.append("</svg>")
    return "\n".join(S)


def write_graph(path: str, g) -> None:
    ext = os.path.splitext(path)[1].lower()
    fn = {".json": to_json, ".dot": to_dot, ".gv": to_dot, ".svg": to_svg}.get(ext)
    if fn is None:
        raise ValueError(f"extensão de --graph não suportada: '{ext}' (use .json, .svg ou .dot)")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(fn(g))
