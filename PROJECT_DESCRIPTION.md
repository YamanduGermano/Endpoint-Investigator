# Endpoint Investigator — Descrição do Projeto (Protótipo)

> Avaliação Intermediária — Tecnologias Hackers (Insper) — Prof. Rodolfo Avelino
> Apresentação: **6 de outubro**

## 1. Objetivo

Ferramenta **sob demanda** (snapshot, sem agente permanente) que investiga um endpoint GNU/Linux e **correlaciona** processos, permissões e serviços para gerar *findings* explicáveis.

Princípios (do enunciado):
- Evidência isolada não prova incidente (nome de processo, root ou permissão ampla **não** bastam).
- Cada finding deve mostrar o **contexto** usado.
- Separar **Evidência → Interpretação → Hipótese → Evidência ausente**.
- Saber dizer **"inconclusivo"**. O objetivo não é achar o máximo de vulnerabilidades.
- Se usar LLM, ele não pode ser a única camada de análise (opcional, fora do protótipo inicial).

**Fluxo:** `COLETA → NORMALIZAÇÃO → CORRELAÇÃO → EVIDÊNCIAS → HIPÓTESES → RESULTADO`

## 2. Stack (protótipo sujo)

| Item | Escolha |
|---|---|
| Linguagem | Python 3.10+ |
| Dependências | Nenhuma (apenas biblioteca padrão: `csv`, `json`, `re`, `argparse`, `dataclasses`, `pathlib`, `datetime`) |
| Entrada | Dataset sintético (`processes.csv`, `permissions.csv`, `services.txt`, `journal.log`) e, opcionalmente, coleta live (`/proc`, `stat`, `systemctl`) |
| Saída | Terminal (texto) + arquivo `report.txt` (opcional `report.json`) |

## 3. Estrutura de pastas

### 3.1 Versão mínima (1 arquivo — recomendada para o protótipo)

```
endpoint-investigator/
├── investigator.py        # TODO o código (coleta, normalização, correlação, relatório)
├── README.md              # arquitetura, execução, correlações, limitações
├── data/                  # dataset de treino (cenário "basic/normal")
│   ├── processes.csv
│   ├── permissions.csv
│   ├── services.txt
│   ├── journal.log
│   ├── metadata.json
│   └── README.txt
└── out/
    └── report.txt         # gerado
```

## 4. Modelo de dados (normalização)

```python
@dataclass Process:   timestamp, pid, ppid, user, stat, cmd, exe, args
@dataclass FileMeta:  path, type, owner, group, mode(int octal), mtime
@dataclass Service:   unit, active, user, execstart, exe, files(list)  # scripts/executáveis referenciados
@dataclass LogEvent:  timestamp, host, source, pid, message
@dataclass Finding:   id, title, severity(info|low|medium|high|inconclusive),
                      evidence[list], interpretation, hypothesis, missing_evidence[list]
```

Esquemas observados no dataset:
- `processes.csv`: `timestamp,pid,ppid,user,stat,cmd`
- `permissions.csv`: `path,type,owner,group,mode,mtime`
- `services.txt`: colunas `UNIT ACTIVE USER EXECSTART` (largura fixa/espaços)
- `journal.log`: formato syslog (`Mon DD HH:MM:SS host proc[pid]: msg`)

## 5. Features

| # | Feature | Fonte(s) | Resultado |
|---|---|---|---|
| F1 | Carregar e normalizar as 4 fontes | CSV/TXT/LOG | Objetos tipados |
| F2 | **Árvore de processos** (PID/PPID) com identidade | processes | Cadeia de ancestrais por processo (ex.: `init → sshd → sshd:aluno → bash → python3`) |
| F3 | **Mapa serviço → processo** | services + processes | Liga unit ao PID (casando executável/cmd) |
| F4 | **Análise de permissões contextual** (só arquivos referenciados) | permissions + services + processes | Flags: world-writable (`o+w`), group-writable, dono não-root em local de sistema |
| F5 | **Correlação C1: Serviço + arquivo + usuário → relação de privilégio** | services + permissions | Serviço root usando recurso gravável por não-privilegiado? |
| F6 | **Correlação C2: Processo + PPID + usuário → contexto de execução** | processes | Origem/cadeia do processo, mudança de usuário, shell interativa, binário em `/home` |
| F7 | **Correlação C3: Processo + serviço + log → linha do tempo** | processes + journal | Timeline unificada ordenada |
| F8 | Classificação **Evidência / Interpretação / Hipótese / Evidência ausente** | todas | Cada finding no formato do enunciado |
| F9 | Severidade com **"inconclusivo"** e rebaixamento por falta de evidência | — | Evita falso positivo |
| F10 | Seção de **limitações / falsos positivos** no relatório | — | Transparência de escopo |
| F11 | Relatório em terminal e `out/report.txt` | — | Saída legível |

Extras opcionais (se sobrar tempo): hash SHA-256 de arquivos referenciados, conexões de rede (`ss -tulpn`) para ligar processo ↔ porta, coleta live.

## 6. Funções (em `investigator.py`)

### Coleta / normalização
| Função | Responsabilidade |
|---|---|
| `load_processes(path) -> list[Process]` | Lê `processes.csv`; separa `exe` e `args` do `cmd` |
| `load_permissions(path) -> dict[str, FileMeta]` | Lê `permissions.csv`; converte `mode` para int octal; indexa por path |
| `load_services(path) -> list[Service]` | Faz parse de `services.txt`; extrai executável do `EXECSTART` |
| `load_journal(path) -> list[LogEvent]` | Regex syslog; converte data (assume ano do dataset via `metadata.json`) |
| `load_metadata(path) -> dict` | Lê `metadata.json` (ano, cenário) |

### Utilitários
| Função | Responsabilidade |
|---|---|
| `build_process_tree(procs) -> dict` | Índice `pid -> Process` e `ppid -> filhos` |
| `ancestry(pid, tree) -> list[Process]` | Cadeia até o PID 1 |
| `is_world_writable(mode) -> bool` | `mode & 0o002` |
| `is_group_writable(mode) -> bool` | `mode & 0o020` |
| `can_unprivileged_modify(meta, user, groups) -> bool` | Dono é o usuário, ou o+w, ou g+w com grupo compatível |
| `extract_referenced_files(service, procs) -> list[str]` | Arquivos/scripts ligados ao serviço (execstart, args de processos filhos, caminhos citados) |
| `match_service_to_process(svc, procs) -> list[Process]` | Casa por executável/cmd |

### Correlação (cada uma retorna `list[Finding]`)
| Função | Correlação |
|---|---|
| `correlate_service_file_privilege(services, perms, procs)` | **C1**: serviço root + arquivo usado + capacidade de escrita por não-privilegiado → "possível relação de privilégio insegura. Isso não prova exploração." |
| `correlate_process_context(procs, tree)` | **C2**: PID+PPID+usuário → contexto (ex.: `python3` de `/home/aluno` iniciado por shell SSH do usuário `aluno`, sem privilégio elevado) |
| `correlate_timeline(procs, services, events)` | **C3**: junta por PID/serviço/horário os eventos (ex.: `sshd 1204` ↔ processo 1204 ↔ log "Accepted publickey") |
| `flag_misconfig_without_link(perms, services, procs)` | Arquivo com permissão ampla **sem** vínculo com serviço privilegiado → finding *informativo/inconclusivo* |

### Findings e relatório
| Função | Responsabilidade |
|---|---|
| `make_finding(...) -> Finding` | Constrói finding com os 4 campos (evidência, interpretação, hipótese, evidência ausente) |
| `score_severity(finding) -> str` | Severidade conforme força das evidências; sem vínculo → `inconclusive`/`info` |
| `render_report(findings, timeline, limits) -> str` | Texto formatado |
| `write_report(text, out_path)` | Grava arquivo |
| `main()` | `argparse` (`--data data/ --out out/report.txt`), executa o fluxo |

### Esqueleto do fluxo
```python
def main():
    args = parse_args()
    procs   = load_processes(f"{args.data}/processes.csv")
    perms   = load_permissions(f"{args.data}/permissions.csv")
    svcs    = load_services(f"{args.data}/services.txt")
    events  = load_journal(f"{args.data}/journal.log")
    tree    = build_process_tree(procs)

    findings  = []
    findings += correlate_service_file_privilege(svcs, perms, procs)
    findings += correlate_process_context(procs, tree)
    findings += flag_misconfig_without_link(perms, svcs, procs)
    timeline  = correlate_timeline(procs, svcs, events)

    report = render_report(findings, timeline, LIMITATIONS)
    print(report); write_report(report, args.out)
```

## 7. Formato de cada finding

```
[F-001] Permissão ampla em /opt/reports/report.sh            severidade: INCONCLUSIVO
  EVIDÊNCIA:        /opt/reports/report.sh  mode=0777  owner=root:root
  INTERPRETAÇÃO:    Arquivo gravável por qualquer usuário (world-writable).
  HIPÓTESE:         Se um serviço privilegiado executar este script, há risco de escalonamento.
  EVIDÊNCIA AUSENTE: Nenhum serviço/processo/cron referencia o arquivo; não há log de modificação.
  CONCLUSÃO:        Configuração inadequada, sem evidência de exploração.
```

## 8. Resultado esperado no dataset fornecido (`basic / normal`)

| Observação no dataset | Tratamento esperado |
|---|---|
| `/opt/reports/report.sh` com `0777` | Finding **inconclusivo** (nenhum serviço o usa — nota didática do README) |
| `ssh`, `apache2`, `cron` rodando como root | **Não** marcar como vulneráveis (root isolado ≠ risco) |
| `python3 /home/aluno/check.py` (PID 1234, user `aluno`, PPID 1212 bash ← sshd 1204) | Contexto benigno: usuário comum, cadeia SSH, log `routine check completed status=OK` |
| `/home/aluno/check.py` vs `/opt/app/check.py` (mesmo nome, locais/donos distintos) | Nota informativa: não confundir pelo nome; o processo executa a cópia do usuário |
| `/etc/shadow` `0640 root:shadow` | Normal; sem finding |
| Timeline | 09:00:00 ssh → 09:00:02 apache2 → 09:00:08 login `aluno` (10.20.30.44) → 09:00:15 python3 OK |

## 9. Limitações / falsos positivos (a declarar)

- Snapshot único: sem histórico, sem detecção de comportamento ao longo do tempo.
- `services.txt` não informa arquivos usados pelos serviços (scripts, cron jobs, units) → vínculo serviço↔arquivo é inferido por heurística (caminho no `EXECSTART`/`cmd`).
- Sem ACLs, capabilities, SUID/SGID, atributos ou herança de diretórios no dataset.
- Casamento por nome/caminho pode gerar falsos positivos/negativos.
- Logs curtos; ausência de evento não prova ausência de atividade.
- Escopo: processos, permissões e serviços + logs; fora do escopo: rede, memória, malware conhecido.

## 10. Plano de implementação (ordem sugerida)

1. Parsers (`load_*`) e dataclasses.
2. Árvore de processos + mapa serviço↔processo.
3. Checagem de permissões contextual (C1).
4. Contexto de execução (C2) e timeline (C3).
5. Classificação evidência/interpretação/hipótese + `inconclusive`.
6. Relatório (terminal + `report.txt`).
7. Gerar datasets com cenários variados (ex.: serviço root executando script `0777` → deve virar finding de risco) para validar que a ferramenta **distingue** o caso normal do suspeito.
8. README + documento técnico (≤ 4 págs) + demo.

## 11. Entregáveis (checklist do enunciado)

- [ ] Código-fonte completo
- [ ] README (arquitetura, dependências, instalação, execução, fontes, correlações, limitações)
- [ ] Documento técnico ≤ 4 páginas (problema, estratégia, arquitetura, correlações, decisões, uso de IA, limitações)
- [ ] Demonstração funcionando sobre dataset de teste

**Pesos:** funcionamento 3,0 · conceitos 2,0 · correlação 2,0 · qualidade evidência/interpretação/hipótese 1,5 · arquitetura/docs 1,0 · demonstração 0,5.