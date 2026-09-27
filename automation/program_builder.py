from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from scope_validator import is_in_scope, parse_scope_pattern
from stages import STAGES, job_name_for

ROOT = Path(__file__).resolve().parent.parent


def program_slug(filename: str, rows: list[dict] | None = None) -> str:
    names = [str(row.get('program_name') or row.get('program') or '').strip() for row in rows or []]
    label = next((name for name in names if name), '') or Path(filename).stem
    slug = re.sub(r'[^a-z0-9]+', '-', label.lower()).strip('-')
    for prefix in ('hackerone-', 'bugcrowd-'):
        if slug.startswith(prefix):
            slug = slug[len(prefix):]
    slug = re.sub(r'(-scope|-targets|-assets|-in-scope)+$', '', slug).strip('-')
    if not slug or len(slug) > 64:
        raise ValueError('A valid program name could not be derived from the scope file')
    return slug


def parse_scope(filename: str, content: str) -> tuple[str, list[str]]:
    extension = Path(filename).suffix.lower()
    candidates: list[str] = []
    exclusions: list[str] = []
    rows = None
    source_name = filename
    if extension == '.md':
        in_scope = False
        out_of_scope = False
        for line in content.splitlines():
            heading = re.match(r'^\s*#{1,6}\s+(.+)', line)
            if heading:
                title = heading.group(1).strip()
                if Path(filename).stem.lower() == 'scope' and line.lstrip().startswith('# ') and source_name == filename:
                    source_name = title + '.md'
                in_scope = bool(re.match(r'^in[ -]scope(?:\b|$)', title, re.IGNORECASE))
                out_of_scope = bool(re.match(r'^out[ -]of[ -]scope(?:\b|$)|^not[ -]in[ -]scope(?:\b|$)', title, re.IGNORECASE))
                continue
            if in_scope or out_of_scope:
                bullet = re.match(r'^\s*[-*]\s+(.+?)\s*$', line)
                if bullet:
                    value = bullet.group(1).strip('`').strip()
                    (candidates if in_scope else exclusions).append(value)
    elif extension == '.csv':
        reader = csv.DictReader(io.StringIO(content.lstrip('\ufeff')))
        if not reader.fieldnames:
            raise ValueError('CSV scope must have a header row')
        rows = []
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError('Malformed CSV scope row')
            rows.append({(key or '').strip().lower().replace(' ', '_'): value.strip()
                         for key, value in row.items()})
        names = {row.get('program_name') or row.get('program') for row in rows}
        names.discard(None)
        names.discard('')
        if len(names) > 1:
            raise ValueError('CSV scope contains multiple programs')
        headers = set(rows[0]) if rows else {field.strip().lower().replace(' ', '_') for field in reader.fieldnames}
        if not headers.intersection({'identifier', 'target', 'asset_identifier', 'asset'}):
            raise ValueError('CSV scope needs an identifier or target column')
        for row in rows:
            allowed = row.get('in_scope', row.get('eligible_for_submission', row.get('eligible_for_bounty', ''))).lower()
            asset_type = (row.get('asset_type') or row.get('type') or '').lower()
            if asset_type not in {'domain', 'wildcard', 'url', 'website'}:
                if allowed in {'true', 'yes', '1'}:
                    raise ValueError('Eligible non-domain assets require manual scope review')
                continue
            value = next((row[key] for key in ('identifier', 'target', 'asset_identifier', 'asset') if row.get(key)), '')
            if asset_type in {'url', 'website'}:
                parsed = urlsplit(value)
                if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
                    continue
                if parsed.path not in {'', '/'} or parsed.query or parsed.fragment:
                    raise ValueError('Path-restricted URL scope requires manual review')
                value = parsed.hostname
            if allowed in {'true', 'yes', '1'}:
                candidates.append(value)
            elif allowed in {'false', 'no', '0'}:
                exclusions.append(value)
    else:
        raise ValueError('Only HackerOne/Bugcrowd CSV or Markdown scope files are supported')

    targets = list(dict.fromkeys(pattern for value in candidates if (pattern := parse_scope_pattern(value))))
    if not targets:
        raise ValueError('No explicitly in-scope domains found; review the file before scanning')
    for value in exclusions:
        pattern = parse_scope_pattern(value)
        if pattern:
            sample = f'probe.{pattern[2:]}' if pattern.startswith('*.') else pattern
            if is_in_scope(sample, targets):
                raise ValueError('Out-of-scope domains overlap in-scope targets; review exclusions manually')
    return program_slug(source_name, rows), targets


def create_program(slug: str, targets: list[str], *, root: Path = ROOT) -> list[str]:
    if not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', slug):
        raise ValueError('Invalid program name')
    if not targets or any(parse_scope_pattern(target) != target for target in targets):
        raise ValueError('Program targets must be valid domain patterns')
    program_dir = root / 'programs' / slug
    jobs_dir = root / 'jobs' / 'generated'
    job_names = [job_name_for(slug, stage['stage']) for stage in STAGES]
    if program_dir.exists() or any((jobs_dir / f'{name}.yaml').exists() for name in job_names):
        raise FileExistsError(f'Program already exists: {slug}')
    program_dir.mkdir(parents=True)
    jobs_dir.mkdir(parents=True, exist_ok=True)
    (program_dir / 'scope.md').write_text(
        f'# {slug} scope\n\n## In-scope targets\n' + ''.join(f'- {target}\n' for target in targets), encoding='utf-8')
    for stage, name in zip(STAGES, job_names):
        dependencies = [job_name_for(slug, dependency) for dependency in stage['depends_on']]
        job_yaml = '\n'.join([
            f'name: {name}', f'program: {slug}', f'stage: {stage["stage"]}',
            f'type: {stage["type"]}', f'order: {stage["step"]}',
            'depends_on: [' + ', '.join(dependencies) + ']', 'targets:',
            *(f'  - {json.dumps(target)}' for target in targets), '',
        ])
        (jobs_dir / f'{name}.yaml').write_text(job_yaml, encoding='utf-8')
    return job_names