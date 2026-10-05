#!/usr/bin/env python3
"""Gerador sintético de exemplo (ponto de partida). Uso: gen_example.py --out DIR [--scenario normal|risk]

Cenário 'risk': serviço root executando script 0777 modificado após o início do serviço.
"""
import argparse, json
from pathlib import Path

ap = argparse.ArgumentParser(); ap.add_argument("--out", required=True)
ap.add_argument("--scenario", choices=["normal", "risk"], default="risk")
a = ap.parse_args()
d = Path(a.out); d.mkdir(parents=True, exist_ok=True)
risk = a.scenario == "risk"

(d / "processes.csv").write_text("\n".join([
    "timestamp,pid,ppid,user,stat,cmd",
    "2026-09-14T09:00:00-03:00,1,0,root,S,/sbin/init",
    "2026-09-14T09:00:02-03:00,612,1,root,S,/usr/sbin/sshd -D",
    "2026-09-14T09:00:04-03:00,701,1,root,S,/usr/sbin/cron -f",
    "2026-09-14T09:00:05-03:00,810,1,root,S,/bin/bash /opt/jobs/backup.sh",
    "2026-09-14T09:00:10-03:00,1204,612,aluno,S,sshd: aluno@pts/0",
    "2026-09-14T09:00:12-03:00,1212,1204,aluno,S,/bin/bash",
]) + "\n")
mode, owner = ("0777", "root") if risk else ("0755", "root")
mt = "2026-09-14T09:00:30-03:00" if risk else "2026-09-10T08:00:00-03:00"
(d / "permissions.csv").write_text("\n".join([
    "path,type,owner,group,mode,mtime",
    "/opt/jobs,directory,root,root,0755,2026-09-10T08:00:00-03:00",
    f"/opt/jobs/backup.sh,file,{owner},root,{mode},{mt}",
    "/etc/shadow,file,root,shadow,0640,2026-09-01T08:00:00-03:00",
]) + "\n")
(d / "services.txt").write_text(
    "UNIT                         ACTIVE   USER      EXECSTART\n"
    "ssh.service                 running  root      /usr/sbin/sshd -D\n"
    "cron.service                running  root      /usr/sbin/cron -f\n"
    "backup.service              running  root      /bin/bash /opt/jobs/backup.sh\n")
(d / "journal.log").write_text(
    "Sep 14 09:00:05 srv systemd[1]: Started backup.service - Backup job.\n"
    "Sep 14 09:00:10 srv sshd[1204]: Accepted publickey for aluno from 10.0.0.5 port 50000 ssh2\n"
    "Sep 14 09:00:31 srv bash[1212]: aluno editou /opt/jobs/backup.sh\n")
(d / "metadata.json").write_text(json.dumps({"dataset_type": "synthetic_training", "level": "basic",
                                              "scenario": a.scenario, "generated_at": "2026-09-24T17:37:37-03:00"}))
