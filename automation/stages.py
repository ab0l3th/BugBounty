"""Canonical workflow stages shared by the worker and dashboard.

The pipeline runs the same eight stages for every bug bounty program. Job files
are program-scoped and named ``<program-slug>-<stage-slug>``; each stage is
identified by a stable ``stage`` id rather than its literal job name so multiple
programs can run side-by-side. Legacy American Airlines job names are mapped back
to their canonical stage for backward compatibility.
"""
from __future__ import annotations

from typing import Dict, List, Optional

# Ordered canonical stages. ``depends_on`` references other stage ids.
STAGES: List[Dict[str, object]] = [
    {
        'stage': 'passive-web-discovery',
        'step': 1,
        'label': 'Passive Web Discovery',
        'type': 'passive',
        'depends_on': [],
    },
    {
        'stage': 'passive-dns-discovery',
        'step': 2,
        'label': 'Passive DNS Discovery',
        'type': 'passive',
        'depends_on': ['passive-web-discovery'],
    },
    {
        'stage': 'confirm-live-web-assets',
        'step': 3,
        'label': 'Confirm Live Web Assets',
        'type': 'active',
        'depends_on': ['passive-web-discovery', 'passive-dns-discovery'],
    },
    {
        'stage': 'service-enumeration',
        'step': 4,
        'label': 'Service Enumeration',
        'type': 'active',
        'depends_on': ['confirm-live-web-assets'],
    },
    {
        'stage': 'vhost-discovery',
        'step': 5,
        'label': 'Vhost Discovery',
        'type': 'active',
        'depends_on': ['service-enumeration'],
    },
    {
        'stage': 'directory-enumeration',
        'step': 6,
        'label': 'Directory Enumeration',
        'type': 'active',
        'depends_on': ['service-enumeration', 'vhost-discovery'],
    },
    {
        'stage': 'application-testing',
        'step': 7,
        'label': 'Application Testing',
        'type': 'active',
        'depends_on': ['directory-enumeration'],
    },
    {
        'stage': 'api-testing',
        'step': 8,
        'label': 'API Testing',
        'type': 'active',
        'depends_on': ['directory-enumeration'],
    },
    {
        'stage': 'port-scan',
        'step': 9,
        'label': 'Port Scan',
        'type': 'active',
        'depends_on': ['vhost-discovery', 'directory-enumeration', 'application-testing'],
    },
]

STAGE_BY_ID: Dict[str, Dict[str, object]] = {stage['stage']: stage for stage in STAGES}

# Stages that make live connections to targets and must run in active mode.
ACTIVE_STAGES = {stage['stage'] for stage in STAGES if stage['type'] == 'active'}

# Existing American Airlines job names predate the canonical stage ids.
LEGACY_NAME_TO_STAGE: Dict[str, str] = {
    'aa-passive-discovery': 'passive-web-discovery',
    'american-airlines-passive-dns': 'passive-dns-discovery',
    'confirm-live-web-assets': 'confirm-live-web-assets',
    'service-enumeration-live-hosts': 'service-enumeration',
    'vhost-discovery-shared-infra': 'vhost-discovery',
    'directory-enumeration-live-hosts': 'directory-enumeration',
    'application-security-testing': 'application-testing',
    'api-endpoint-testing': 'api-testing',
    'port-scan-live-hosts': 'port-scan',
}


def stage_for_job_name(job_name: str) -> Optional[str]:
    """Resolve a job name to its canonical stage id.

    Recognizes legacy AA names and the generic ``<slug>-<stage-slug>`` pattern.
    """
    name = (job_name or '').strip()
    if not name:
        return None
    if name in LEGACY_NAME_TO_STAGE:
        return LEGACY_NAME_TO_STAGE[name]
    # Longest stage-slug suffix wins so e.g. 'passive-dns-discovery' is not
    # shadowed by a shorter id.
    for stage_id in sorted(STAGE_BY_ID, key=len, reverse=True):
        if name == stage_id or name.endswith('-' + stage_id):
            return stage_id
    return None


def stage_metadata(stage_id: str) -> Dict[str, object]:
    stage = STAGE_BY_ID.get(stage_id)
    if not stage:
        return {'stage': stage_id, 'step': 99, 'label': stage_id, 'type': 'passive', 'depends_on': []}
    return dict(stage)


def job_name_for(program_slug: str, stage_id: str) -> str:
    """Generic job name for a program's stage, e.g. 'google-service-enumeration'."""
    return f'{program_slug}-{stage_id}'
