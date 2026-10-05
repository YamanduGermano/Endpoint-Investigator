# Endpoint Investigator (protótipo v0.2)

Investigação sob demanda de endpoints Linux: **COLETA → NORMALIZAÇÃO → CORRELAÇÃO → EVIDÊNCIAS → HIPÓTESES → RESULTADO**.
Python 3.10+, só biblioteca padrão.

## Uso
Sem parâmetros o programa imprime o help. Escolha **um** modo:

| Modo | Comando |
|---|---|
| Dataset | `python3 investigator.py --dataset data/` |
| Snapshot atual | `sudo python3 investigator.py --live` |
| Script gerador | `python3 investigator.py --script samples/generate_dataset.py.py [--script-args "--out {out} --scenario normal"] [--keep DIR]` |

Opções: `--out FILE` (relatório), `--json FILE` (findings), `--graph FILE` (repetível; `.svg` imagem, `.json` estruturado, `.dot` Graphviz), `--graph-full`, `-q`.

Contrato do script: por padrão é chamado como `script --out <DIR>` e deve gravar `processes.csv`, `permissions.csv`, `services.txt` (+ `journal.log`, `metadata.json`). `{out}` e `EI_OUTPUT_DIR` apontam para o diretório temporário.

## Estrutura
```
investigator.py            CLI e orquestração
ei/models.py               dataclasses (Process, FileMeta, Service, LogEvent, Snapshot, Finding)
ei/utils.py                parsing de cmd, permissões, árvore de processos
ei/collectors/dataset.py   modo --dataset (também parser de journal)
ei/collectors/live.py      modo --live (/proc, stat, systemctl, journalctl)
ei/collectors/custom.py    modo --script
ei/correlators/            servicemap, service_perm (C1), process_context (C2), timeline (C3), misconfig
ei/report.py               relatório texto + JSON
ei/graph.py                grafo de relações -> JSON / DOT / SVG
samples/generate_dataset.py.py     gerador sintético de exemplo
data/, data_risk/          datasets de teste (normal e com risco)
```

## Limitações
Snapshot único; vínculo serviço↔arquivo heurístico; sem ACLs/capabilities/SUID/crontabs/rede; no modo live sem root a visão é parcial;
em containers sem systemd não há serviços. Severidade é priorização, não veredito.
