"""Coletor 3: executa um script customizado que gera dados sintéticos e carrega o resultado.

Contrato do script (padrão): `python3 script.py --out <DIR>` grava processes.csv, permissions.csv,
services.txt e (opcional) journal.log em <DIR> (ou numa subpasta dele). O diretório também é
exposto na variável de ambiente EI_OUTPUT_DIR. Use --script-args para outro formato de chamada;
'{out}' é substituído pelo diretório temporário.
"""
from __future__ import annotations
import os, shlex, shutil, subprocess, sys, tempfile
from pathlib import Path
from .dataset import collect_dataset, find_dataset_root


def collect_from_script(script, script_args=None, keep=None):
    sp = Path(script).resolve()
    if not sp.is_file():
        raise FileNotFoundError(f"script não encontrado: {script}")
    tmp = Path(tempfile.mkdtemp(prefix="ei_dataset_"))
    try:
        args = shlex.split(script_args) if script_args else ["--out", "{out}"]
        args = [a.replace("{out}", str(tmp)) for a in args]
        cmd = ([sys.executable, str(sp)] if sp.suffix == ".py" else [str(sp)]) + args
        print(f"[!] executando script externo (confie apenas em scripts que você revisou): {' '.join(cmd)}", file=sys.stderr)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=tmp, env={**os.environ, "EI_OUTPUT_DIR": str(tmp)})
        if r.returncode != 0:
            raise RuntimeError(f"script terminou com código {r.returncode}:\n{(r.stderr or r.stdout)[-600:]}")
        root = find_dataset_root(tmp)
        if root is None:
            raise RuntimeError("o script não gerou processes.csv/permissions.csv/services.txt em <out>.\n"
                               f"saída do script:\n{(r.stdout + r.stderr)[-400:]}")
        snap = collect_dataset(root)
        snap.mode, snap.source = "script", f"{sp} -> dataset gerado"
        if keep:
            shutil.copytree(root, keep, dirs_exist_ok=True)
            snap.warnings.append(f"dataset gerado preservado em {keep}")
        return snap
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
