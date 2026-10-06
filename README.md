# Endpoint Investigator (protótipo v0.2)

Investigação sob demanda de endpoints Linux: **COLETA → NORMALIZAÇÃO → CORRELAÇÃO → EVIDÊNCIAS → HIPÓTESES → RESULTADO**.
Python 3.10+, só biblioteca padrão.

## Vídeo Demonstração para Exemplo de Utilização

- Segue o vídeo para demonstração, necessário para a entrega, e que pode ser usado como referência para a avaliação do protótipo: [Vídeo Demonstração](https://youtu.be/GRqNC8juIws)

## Uso
Sem parâmetros o programa imprime o help. Escolha **um** modo:

| Modo | Comando |
|---|---|
| Dataset | `python3 investigator.py --dataset data/` |
| Snapshot atual | `sudo python3 investigator.py --live` |
| Script gerador | `python3 investigator.py --script samples/generate_dataset.py [--script-args "--out {out} --scenario normal"] [--keep DIR]` |

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
## Correlações exploradas
| Função | Correlação |
|---|---|
| `correlate_service_file_privilege(services, perms, procs)` | **C1**: serviço root + arquivo usado + capacidade de escrita por não-privilegiado → "possível relação de privilégio insegura. Isso não prova exploração." |
| `correlate_process_context(procs, tree)` | **C2**: PID+PPID+usuário → contexto (ex.: `python3` de `/home/aluno` iniciado por shell SSH do usuário `aluno`, sem privilégio elevado) |
| `correlate_timeline(procs, services, events)` | **C3**: junta por PID/serviço/horário os eventos (ex.: `sshd 1204` ↔ processo 1204 ↔ log "Accepted publickey") |
| `flag_misconfig_without_link(perms, services, procs)` | Arquivo com permissão ampla **sem** vínculo com serviço privilegiado → finding *informativo/inconclusivo* |

## Limitações
- Snapshot único: não observa evolução temporal nem histórico completo (caso Postgres do vídeo de Demonstração)
- O vínculo serviço-arquivo e heurístico e pode produzir falsos positivos ou negativos.
- Não observamos alguns aspectos que poderiam refinar/ampliar nossas conclusões,
SUID/SGID, atributos, crontabs, units completas, rede e memória.
- Logs curtos e ausência de evento não provam ausência de atividade.
- Sem hash, conteúdo ou auditd, não se confirma que um arquivo foi alterado ou executado.
- No modo live sem root, a visão de processos e arquivos pode ser parcial, mas a própria execução do Python por meio de um “sudo” já gera um caso falso positivo de alta vulnerabilidade

