#!/usr/bin/env python3
"""Endpoint Investigator — ponto de entrada (CLI).

COLETA -> NORMALIZAÇÃO -> CORRELAÇÃO -> EVIDÊNCIAS -> HIPÓTESES -> RESULTADO
"""
from __future__ import annotations
import argparse, sys
from pathlib import Path
from ei import __version__
from ei.collectors import collect_dataset, collect_live, collect_from_script
from ei.correlators import run_all
from ei.graph import build_graph, write_graph
from ei.report import render_report, findings_json

EPILOG = """\
modos de operação (escolha exatamente um):
  --dataset DIR    analisa um diretório de dataset (processes.csv, permissions.csv, services.txt, journal.log)
  --live           gera e analisa um snapshot do sistema atual (Linux; use root para visão completa)
  --script FILE    executa um script customizado que gera dados sintéticos e analisa o resultado

exemplos:
  python3 investigator.py --dataset data/
  python3 investigator.py --dataset data_risk/ --graph out/mapa.svg --graph out/mapa.json
  sudo python3 investigator.py --live --out out/live.txt --graph out/live.svg
  python3 investigator.py --script samples/gen_example.py --keep out/gerado
"""


def build_parser():
    ap = argparse.ArgumentParser(prog="investigator.py", description=f"Endpoint Investigator v{__version__} — investigação de endpoints Linux por correlação de evidências",
                                 epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_argument_group("modo de operação (obrigatório, mutuamente exclusivo)")
    g.add_argument("--dataset", metavar="DIR", help="diretório do dataset de entrada")
    g.add_argument("--live", action="store_true", help="snapshot do sistema atual")
    g.add_argument("--script", metavar="FILE", help="script customizado gerador de dados sintéticos")
    o = ap.add_argument_group("opções")
    o.add_argument("--script-args", metavar="ARGS", help="argumentos do script ('{out}' = diretório de saída; padrão: '--out {out}')")
    o.add_argument("--keep", metavar="DIR", help="(--script) preserva o dataset gerado neste diretório")
    o.add_argument("--out", metavar="FILE", help="grava o relatório de texto neste arquivo")
    o.add_argument("--json", metavar="FILE", help="grava os findings em JSON estruturado")
    o.add_argument("--graph", metavar="FILE", action="append",
                   help="gera o mapa de relações; formato pela extensão: .svg (imagem), .json (estruturado), .dot (Graphviz). Repetível")
    o.add_argument("--graph-full", action="store_true", help="inclui TODOS os processos no mapa (padrão: só os relevantes)")
    o.add_argument("-q", "--quiet", action="store_true", help="não imprime o relatório no terminal")
    return ap


def main(argv=None) -> int:
    ap = build_parser()
    argv = sys.argv[1:] if argv is None else argv
    if not argv:                                   # sem parâmetros: mostra ajuda
        ap.print_help()
        return 2
    a = ap.parse_args(argv)
    modes = [bool(a.dataset), a.live, bool(a.script)]
    if sum(modes) != 1:
        ap.error("escolha exatamente um modo: --dataset DIR | --live | --script FILE")
    try:
        if a.dataset:
            snap = collect_dataset(a.dataset)
        elif a.live:
            snap = collect_live()
        else:
            snap = collect_from_script(a.script, a.script_args, a.keep)
        an = run_all(snap)
        report = render_report(snap, an)
        if not a.quiet:
            print(report)
        if a.out:
            Path(a.out).parent.mkdir(parents=True, exist_ok=True)
            Path(a.out).write_text(report, encoding="utf-8")
        if a.json:
            Path(a.json).parent.mkdir(parents=True, exist_ok=True)
            Path(a.json).write_text(findings_json(an), encoding="utf-8")
        if a.graph:
            g = build_graph(snap, an, a.graph_full)
            for path in a.graph:
                write_graph(path, g)
                print(f"[graph] {path}: {len(g['nodes'])} nós, {len(g['edges'])} arestas", file=sys.stderr)
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        print(f"erro: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())