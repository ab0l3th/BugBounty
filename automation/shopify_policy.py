from __future__ import annotations

import csv
import fnmatch
import json
import os
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit


BLOCKED_HOSTS = {
    'your-store.myshopify.com', 'cdn.shopify.com', 'static.shopify.com', 'community.shopify.com',
    'community.shopify.dev', 'livechat.shopify.com', 'academy.shopify.com', 'investors.shopify.com',
    'supplier-portal.shopifycloud.com', 'vendorvoice.shopifycloud.com', 'nsolid-test-console.shopifycloud.com',
    'invoices.shopify.io', 'factures.shopify.io', 'invoices.shopify.cn', 'invoices.shopify.de',
    'invoices.shopify.fr', 'invoices.shopify.jp',
}
REVIEW_SUFFIXES = ('.shopifycloud.com', '.shopifykloud.com', '.shopify.io')


def is_shopify_program(slug: str, root: Path) -> bool:
    if slug == 'shopify':
        return True
    try:
        rules = (root / 'programs' / slug / 'rules.md').read_text(encoding='utf-8').lower()
        return "shopify's bug bounty" in rules or 'shopify bug bounty program' in rules
    except OSError:
        return False


def load_controls(slug: str, root: Path) -> dict:
    try:
        data = json.loads((root / 'programs' / slug / '.shopify-controls.json').read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def register_pending_store(slug: str, hostname: str, root: Path) -> dict:
    if not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', slug) or not is_shopify_program(slug, root):
        raise ValueError('Not a Shopify bounty')
    hostname = hostname.strip().lower().rstrip('.')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}\.myshopify\.com', hostname) or hostname == 'your-store.myshopify.com':
        raise ValueError('Supply an actual development-store hostname')
    directory = root / 'programs' / slug
    if not directory.is_dir():
        raise FileNotFoundError('Shopify bounty not found')
    controls = load_controls(slug, root)
    stores = controls.setdefault('owned_stores', [])
    existing = next((store for store in stores if isinstance(store, dict) and store.get('hostname') == hostname), None)
    if existing is None:
        existing = {'hostname': hostname, 'user_identified_owned': True, 'hackerone_alias_confirmed': False,
                    'testing_enabled': False, 'status': 'pending_setup_confirmation'}
        stores.append(existing)
    path = directory / '.shopify-controls.json'
    temporary = path.with_name('.shopify-controls.json.tmp')
    temporary.write_text(json.dumps(controls, indent=2), encoding='utf-8')
    temporary.chmod(0o600)
    temporary.replace(path)
    return existing


def host_allowed(hostname: str, slug: str, root: Path) -> bool:
    if not is_shopify_program(slug, root):
        return True
    hostname = hostname.lower().rstrip('.')
    if any(hostname == blocked or hostname.endswith('.' + blocked) for blocked in BLOCKED_HOSTS) or fnmatch.fnmatchcase(hostname, '*.email.shopify.com') or fnmatch.fnmatchcase(hostname, 'devdegree*.shopifycloud.com'):
        return False
    controls = load_controls(slug, root)
    if hostname == 'myshopify.com' or hostname.endswith('.myshopify.com'):
        return any(isinstance(store, dict) and store.get('hostname') == hostname and store.get('user_identified_owned') is True
                   and store.get('hackerone_alias_confirmed') is True and store.get('testing_enabled') is True
                   for store in controls.get('owned_stores', []))
    if hostname.endswith(REVIEW_SUFFIXES):
        if hostname in controls.get('reviewed_platform_hosts', []):
            return True
        try:
            with (root / 'programs' / slug / 'scope-source.csv').open(encoding='utf-8-sig') as source:
                for row in csv.DictReader(source):
                    if row.get('identifier', '').lower().rstrip('.') == hostname and row.get('asset_type', '').upper() == 'URL':
                        return row.get('eligible_for_bounty', '').lower() in {'true', 'yes', '1'} and row.get('eligible_for_submission', '').lower() in {'true', 'yes', '1'}
        except OSError:
            pass
        return False
    return True


def apply_finding_eligibility(payload: dict, root: Path) -> dict:
    if not is_shopify_program(payload.get('program', ''), root):
        return payload
    for asset in payload.get('assets', []) or []:
        if not isinstance(asset, dict):
            continue
        retained = []
        observations = list(asset.get('policy_observations', []))
        for finding in asset.get('findings', []) or []:
            if not isinstance(finding, dict):
                continue
            path = str(finding.get('path', '')).split('?', 1)[0].rstrip('/')
            intentional = finding.get('type') == 'graphql_introspection' or finding.get('type') == 'debug_endpoint' and path.endswith('/graphql')
            if intentional:
                observations.append({**finding, 'report_eligible': False, 'severity': 'info',
                                     'reason': 'Shopify intentionally exposes GraphQL introspection; not eligible alone'})
            else:
                retained.append(finding)
        asset['findings'] = retained
        if observations:
            asset['policy_observations'] = observations
    return payload


def url_allowed(url: str, slug: str, root: Path) -> bool:
    if not is_shopify_program(slug, root):
        return True
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    if not parsed.hostname or not host_allowed(parsed.hostname, slug, root):
        return False
    if parsed.hostname == 'admin.shopify.com' and parsed.path.startswith('/store/'):
        store = parsed.path.split('/')[2]
        if not host_allowed(store + '.myshopify.com', slug, root):
            return False
    for key in ('shop', 'store'):
        for value in parse_qs(parsed.query).get(key, []):
            if value.endswith('.myshopify.com') and not host_allowed(value, slug, root):
                return False
    return True