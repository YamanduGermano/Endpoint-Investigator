"""Orquestra as correlações e devolve o resultado da análise."""
from __future__ import annotations
from dataclasses import dataclass
from ..models import SEV_ORDER
from ..utils import build_process_tree
from .servicemap import build_service_map
from .service_perm import correlate_service_file_privilege, correlate_identity_mismatch
from .process_context import correlate_process_context
from .misconfig import flag_misconfig_without_link
from .timeline import correlate_timeline


@dataclass
class Analysis:
    smap: list
    findings: list
    timeline: list
    by_pid: dict
    kids: dict


def run_all(snap) -> Analysis:
    by_pid, kids = build_process_tree(snap.processes)
    smap = build_service_map(snap.services, snap.processes, kids)
    svc_pids = {p.pid for e in smap for p, _ in e["procs"]}
    findings = []
    findings += correlate_service_file_privilege(smap, snap.perms)
    findings += correlate_identity_mismatch(smap)
    findings += correlate_process_context(snap.processes, by_pid, snap.perms, snap.events, svc_pids)
    findings += flag_misconfig_without_link(snap.perms, smap, snap.processes, snap.services)
    relevant = set(svc_pids) | {pid for f in findings for pid in f.refs.get("pids", [])} \
        | {e.pid for e in snap.events if e.pid in by_pid}
    timeline, tl_findings = correlate_timeline(snap, by_pid, relevant)
    findings += tl_findings
    findings.sort(key=lambda f: SEV_ORDER[f.severity])
    for i, f in enumerate(findings, 1):
        f.id = f"F-{i:03d}"
    return Analysis(smap, findings, timeline, by_pid, kids)
