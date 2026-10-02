from __future__ import annotations

import csv
from collections import Counter
import hashlib
import io
import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

from scope_validator import is_in_scope, parse_scope_pattern
from stages import STAGES, job_name_for

ROOT = Path(__file__).resolve().parent.parent


def slug_from_program_name(name: str) -> str:
    label = name.strip()
    if not label or len(label) > 80 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]*', label):
        raise ValueError('Enter a program name using letters, numbers, spaces, dots, dashes, or underscores')
    slug = re.sub(r'[^a-z0-9]+', '-', label.lower()).strip('-')
    if not slug or len(slug) > 64:
        raise ValueError('Program name is too long')
    return slug


def csv_scope_inventory(content: str) -> dict:
    reader = csv.DictReader(io.StringIO(content.lstrip('\ufeff')))
    columns = {(column or '').strip().lower().replace(' ', '_') for column in reader.fieldnames or []}
    if not columns.intersection({'identifier', 'target', 'asset_identifier', 'asset'}) or not columns.intersection(
        {'in_scope', 'eligible_for_submission', 'eligible_for_bounty'}
    ):
        raise ValueError('CSV scope needs identifier and eligibility columns')
    counts: dict[str, int] = {}
    manual_only = False
    rows = 0
    for raw in reader:
        if None in raw or any(value is None for value in raw.values()):
            raise ValueError('Malformed CSV scope row')
        row = {(key or '').strip().lower().replace(' ', '_'): value.strip() for key, value in raw.items()}
        flag = row.get('in_scope', row.get('eligible_for_submission', row.get('eligible_for_bounty', ''))).lower()
        kind = (row.get('asset_type') or row.get('type') or '').upper()
        if flag not in {'true', 'yes', '1', 'false', 'no', '0'} or not kind:
            raise ValueError('CSV scope has an ambiguous eligibility or asset type')
        identifier = next((row[key] for key in ('identifier', 'target', 'asset_identifier', 'asset') if row.get(key)), '')
        if not identifier:
            raise ValueError('CSV scope has an asset without an identifier')
        rows += 1
        if kind == 'URL':
            manual_only = True
        if flag in {'true', 'yes', '1'}:
            counts[kind] = counts.get(kind, 0) + 1
            if kind not in {'DOMAIN', 'WILDCARD'}:
                manual_only = True
    if not counts:
        raise ValueError('No explicitly eligible assets found')
    return {'eligible_asset_types': counts, 'total_rows': rows, 'manual_only': manual_only}


def analyze_url_scope(content: str, guidelines: str) -> dict:
    inventory = csv_scope_inventory(content)
    assets: list[dict] = []
    app_assets: list[dict] = []
    seen: set[str] = set()
    invalid_urls = 0
    for raw in csv.DictReader(io.StringIO(content.lstrip('\ufeff'))):
        row = {(key or '').strip().lower().replace(' ', '_'): (value or '').strip() for key, value in raw.items()}
        if row.get('in_scope', row.get('eligible_for_submission', row.get('eligible_for_bounty', ''))).lower() not in {'true', 'yes', '1'}:
            continue
        if (row.get('asset_type') or row.get('type') or '').upper() != 'URL':
            kind = (row.get('asset_type') or row.get('type') or '').upper()
            if kind in {'GOOGLE_PLAY_APP_ID', 'APPLE_STORE_APP_ID'} and row.get('in_scope', row.get('eligible_for_submission', row.get('eligible_for_bounty', ''))).lower() in {'true', 'yes', '1'}:
                identifier = next((row[key] for key in ('identifier', 'target', 'asset_identifier', 'asset') if row.get(key)), '')
                app_assets.append({'platform': 'Google Play' if kind == 'GOOGLE_PLAY_APP_ID' else 'Apple App Store',
                                   'identifier': identifier})
            continue
        value = next((row[key] for key in ('identifier', 'target', 'asset_identifier', 'asset') if row.get(key)), '')
        bare_host = parse_scope_pattern(value)
        if bare_host == value.lower().rstrip('.') and '*' not in value:
            identity = hashlib.sha256(value.encode('utf-8')).hexdigest()
            if identity in seen:
                continue
            seen.add(identity)
            host = value.lower().rstrip('.')
            category = ('login' if re.search(r'(^|[.-])(?:login|signin|sign-in|sso)([.-]|$)', host, re.IGNORECASE)
                        else 'api' if re.search(r'(^|[.-])api([.-]|$)', host, re.IGNORECASE) else 'web')
            assets.append({'id': identity, 'scheme': None, 'host': host, 'port': None,
                           'path': '/', 'query_present': False, 'category': category,
                           'scope_kind': 'exact_host'})
            continue
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError:
            invalid_urls += 1
            continue
        if parsed.scheme not in {'https', 'http'} or not parsed.hostname or parsed.username or parsed.password:
            invalid_urls += 1
            continue
        identity = hashlib.sha256(value.encode('utf-8')).hexdigest()
        if identity in seen:
            continue
        seen.add(identity)
        path = parsed.path or '/'
        category = ('login' if re.search(r'/(?:login|signin|sign-in|sso)(?:/|$)', path, re.IGNORECASE)
                    else 'api' if re.search(r'/api(?:/|$)', path, re.IGNORECASE) else 'web')
        assets.append({'id': identity, 'scheme': parsed.scheme, 'host': parsed.hostname,
                       'port': port, 'path': path, 'query_present': bool(parsed.query),
                       'category': category, 'scope_kind': 'exact_url'})
    rate_match = re.search(r'(?:not exceed|maximum|limit of)\s+(\d+)\s+requests?\s+per\s+second', guidelines, re.IGNORECASE)
    stated_limit = int(rate_match.group(1)) if rate_match else None
    hard_ban = re.search(r'(?:\bno\s+|(?:do not|must not|prohibit(?:ed)?|not allowed)[^.!?\n]{0,50})automated\s+(?:requests?|testing|scans?)|automated\s+(?:requests?|testing|scans?)\s+(?:are\s+|is\s+)?(?:prohibited|not allowed|forbidden)', guidelines, re.IGNORECASE)
    if hard_ban:
        automation_status = 'blocked'
        reason = 'Guidelines explicitly prohibit automated requests or scans'
    elif stated_limit:
        automation_status = 'manual_approval_required'
        reason = 'Only operator-approved bounded exact-scope checks are available; aggressive scanning remains disabled. Rate limits are not permission; automated findings may be ineligible and require manual verification'
    else:
        automation_status = 'blocked'
        reason = 'No explicit request-rate limit was found in the guidelines'
    policy = {'automated_requests': automation_status,
              'stated_max_requests_per_second': stated_limit,
              'max_requests_per_second': min(1, stated_limit) if stated_limit else None,
              'method': 'HEAD', 'follows_redirects': True, 'max_redirects': 3,
              'skips_login_redirects': True, 'redirects_must_be_in_scope': True, 'reason': reason}
    return {'eligible_urls': inventory['eligible_asset_types'].get('URL', 0), 'invalid_urls': invalid_urls,
            'app_ids': len(app_assets), 'app_assets': app_assets,
            'categories': dict(Counter(asset['category'] for asset in assets)),
            'policy': policy, 'assets': assets}


def load_manual_analysis(slug: str, *, root: Path = ROOT) -> dict:
    if not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', slug):
        raise ValueError('Invalid program name')
    program_dir = root / 'programs' / slug
    if not (program_dir / 'scope-inventory.json').is_file():
        raise FileNotFoundError('Manual program inventory not found')
    return analyze_url_scope((program_dir / 'scope-source.csv').read_text(encoding='utf-8'),
                             (program_dir / 'rules.md').read_text(encoding='utf-8'))


def create_manual_program(slug: str, scope_content: str, guidelines: str, inventory: dict, *, root: Path = ROOT) -> None:
    if not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', slug):
        raise ValueError('Invalid program name')
    if not guidelines.strip() or len(guidelines.encode('utf-8')) > 256 * 1024:
        raise ValueError('Program guidelines must contain text under 256 KB')
    program_dir = root / 'programs' / slug
    if program_dir.exists() or any((root / 'jobs' / 'generated').glob(f'{slug}-*.yaml')):
        raise FileExistsError(f'Program already exists: {slug}')
    program_dir.mkdir(parents=True)
    (program_dir / 'scope.md').write_text(
        f'# {slug} scope\n\n## Manual review required\nNo automated targets. Source CSV is preserved separately.\n', encoding='utf-8')
    source = program_dir / 'scope-source.csv'
    source.write_text(scope_content, encoding='utf-8')
    source.chmod(0o600)
    (program_dir / 'rules.md').write_text(guidelines.strip() + '\n', encoding='utf-8')
    (program_dir / 'scope-inventory.json').write_text(json.dumps(inventory, indent=2), encoding='utf-8')


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


def read_guidelines(slug: str, *, root: Path = ROOT) -> tuple[str, str]:
    if not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', slug):
        raise ValueError('Invalid program name')
    text = (root / 'programs' / slug / 'rules.md').read_text(encoding='utf-8')
    if not text.strip():
        raise ValueError('Program guidelines are empty')
    return text, hashlib.sha256(text.encode('utf-8')).hexdigest()


def active_approved(slug: str, *, root: Path = ROOT) -> bool:
    try:
        _, digest = read_guidelines(slug, root=root)
        decision = json.loads((root / 'programs' / slug / '.active-approval.json').read_text(encoding='utf-8'))
        return decision.get('approved') is True and decision.get('guidelines_sha256') == digest
    except (OSError, ValueError, AttributeError):
        return False


def set_active_approval(slug: str, approved: bool, digest: str, *, root: Path = ROOT) -> None:
    _, current_digest = read_guidelines(slug, root=root)
    if digest != current_digest:
        raise ValueError('Guidelines changed; review the current document before approving')
    path = root / 'programs' / slug / '.active-approval.json'
    temporary = path.with_name('.active-approval.json.tmp')
    temporary.write_text(json.dumps({'approved': approved, 'guidelines_sha256': digest,
                                     'reviewed_at': int(time.time())}), encoding='utf-8')
    temporary.replace(path)


def create_program(slug: str, targets: list[str], *, root: Path = ROOT, guidelines: str | None = None) -> list[str]:
    if not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', slug):
        raise ValueError('Invalid program name')
    if not targets or any(parse_scope_pattern(target) != target for target in targets):
        raise ValueError('Program targets must be valid domain patterns')
    if guidelines is not None and (not guidelines.strip() or len(guidelines.encode('utf-8')) > 256 * 1024):
        raise ValueError('Program guidelines must contain text under 256 KB')
    program_dir = root / 'programs' / slug
    jobs_dir = root / 'jobs' / 'generated'
    job_names = [job_name_for(slug, stage['stage']) for stage in STAGES]
    if program_dir.exists() or any((jobs_dir / f'{name}.yaml').exists() for name in job_names):
        raise FileExistsError(f'Program already exists: {slug}')
    program_dir.mkdir(parents=True)
    jobs_dir.mkdir(parents=True, exist_ok=True)
    (program_dir / 'scope.md').write_text(
        f'# {slug} scope\n\n## In-scope targets\n' + ''.join(f'- {target}\n' for target in targets), encoding='utf-8')
    if guidelines is not None:
        (program_dir / 'rules.md').write_text(guidelines.strip() + '\n', encoding='utf-8')
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