from __future__ import annotations

from contextlib import contextmanager
import json
import os
import re
import signal
import time
from pathlib import Path
from urllib import request
from stages import stage_for_job_name
from vhost_transport import VhostRedirectHandler, vhost_opener

_DEFAULT_URLOPEN = request.urlopen


class JobStopped(RuntimeError):
    pass


def _safe_name(name: str) -> str:
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,159}', name):
        raise ValueError('Invalid job name')
    return name


def stop_path(root: Path, name: str) -> Path:
    return root / 'results' / '.stopped' / f'{_safe_name(name)}.json'


def is_stopped(root: Path, name: str) -> bool:
    return stop_path(root, name).is_file()


def check_stop(root: Path, name: str) -> None:
    if is_stopped(root, name):
        raise JobStopped('Stopped by operator; explicit restart required')


def clear_stop(root: Path, name: str) -> None:
    if is_stopped(root, name):
        result = root / 'results' / f'{_safe_name(name)}.json'
        try:
            saved = json.loads(result.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            saved = None
        if saved is not None:
            _write(root / 'results' / '.stopped-results' / f'{name}.json', saved)
    stop_path(root, name).unlink(missing_ok=True)


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    temporary.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    temporary.replace(path)


def process_identity(pid: int) -> dict | None:
    try:
        directory = Path('/proc') / str(pid)
        stat = (directory / 'stat').read_text()
        fields = stat[stat.rfind(')') + 2:].split()
        if fields[0] == 'Z':
            return None
        arguments = (directory / 'cmdline').read_bytes().decode('utf-8', 'replace').split('\0')
        uptime = float(Path('/proc/uptime').read_text().split()[0])
        started = time.time() - uptime + int(fields[19]) / os.sysconf('SC_CLK_TCK')
        return {'pid': pid, 'start_ticks': fields[19], 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'arguments': [argument for argument in arguments if argument], 'started_at': started}
    except (OSError, ValueError, IndexError):
        return None


def mark_stopped_result(root: Path, name: str) -> None:
    path = root / 'results' / f'{_safe_name(name)}.json'
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        payload = {'job': name, 'assets': [], 'discovered': []}
    was_running = payload.get('stop_was_running', payload.get('job_state') == 'running' or payload.get('status') == 'running')
    payload.update({'status': 'stopped', 'job_state': 'stopped', 'stop_requested': True, 'stop_was_running': was_running,
                    'reason': 'Stopped by operator; explicit restart required'})
    _write(path, payload)


def request_stop(root: Path, name: str, program: str, *, candidate_pid=None) -> dict:
    path = stop_path(root, name)
    _write(path, {'job': name, 'program': program, 'requested_at': int(time.time())})
    signaled = False
    cooperative = False
    identity = None
    if candidate_pid:
        identity = process_identity(candidate_pid)
        owner_path = root / 'results' / '.running' / '.owners' / f'{name}.json'
        try:
            owner = json.loads(owner_path.read_text())
        except (OSError, ValueError):
            owner = {}
        cooperative = bool(identity and owner.get('job') == name and owner.get('program') == program and owner.get('pid') == candidate_pid
                           and owner.get('start_ticks') == identity['start_ticks'] and owner.get('boot_id') == identity['boot_id'])
        lock = root / 'results' / '.running' / f'{name}.lock'
        try:
            lock_pid = int(lock.read_text().strip())
            current_lock = lock_pid == candidate_pid and identity and lock.stat().st_mtime + 2 >= identity['started_at']
        except (OSError, ValueError):
            current_lock = False
        if identity and current_lock and not cooperative:
            arguments = identity['arguments']
            script_index = next((index for index, argument in enumerate(arguments)
                                 if Path(argument).resolve() == (root / 'automation/worker.py').resolve()), None)
            if script_index is not None:
                scoped = '--program' not in arguments or arguments[arguments.index('--program') + 1:arguments.index('--program') + 2] == [program]
                selected = '--job' not in arguments or arguments[arguments.index('--job') + 1:arguments.index('--job') + 2] == [name]
                conflicting = []
                for other in lock.parent.glob('*.lock'):
                    if other == lock or other.name.startswith(('auto-program-', 'manual-program-', 'manual-url-check-')):
                        continue
                    try:
                        if int(other.read_text().strip()) == candidate_pid and other.stat().st_mtime + 2 >= identity['started_at']:
                            conflicting.append(other)
                    except (OSError, ValueError):
                        continue
                current = process_identity(candidate_pid)
                if scoped and selected and not conflicting and current and current['start_ticks'] == identity['start_ticks'] and current['boot_id'] == identity['boot_id']:
                    try:
                        os.kill(candidate_pid, signal.SIGTERM)
                        signaled = True
                    except ProcessLookupError:
                        pass
        if identity and not signaled and not cooperative:
            arguments = identity['arguments']
            manual_script = str((root / 'automation/manual_workflow.py').resolve())
            if manual_script in arguments:
                index = arguments.index(manual_script)
                expected = [program, stage_for_job_name(name)]
                program_lock = root / 'results' / '.running' / f'manual-program-{program}.lock'
                try:
                    valid_lock = int(program_lock.read_text().strip()) == candidate_pid and program_lock.stat().st_mtime + 2 >= identity['started_at']
                except (OSError, ValueError):
                    valid_lock = False
                current = process_identity(candidate_pid)
                if arguments[index + 1:index + 3] == expected and valid_lock and current and current['start_ticks'] == identity['start_ticks'] and current['boot_id'] == identity['boot_id']:
                    try:
                        os.kill(candidate_pid, signal.SIGTERM)
                        signaled = True
                    except ProcessLookupError:
                        pass
    mark_stopped_result(root, name)
    message = 'Stop saved; partial results retained. Explicit restart required.'
    if cooperative:
        message = 'Stop requested; waiting for the in-flight operation to finish. Explicit restart required.'
    elif signaled:
        message = 'Stop signal sent to the verified worker; partial results retained.'
    elif identity:
        message = 'Stop hold saved, but the running process could not be safely verified and was not signaled.'
    return {'status': 'stopped', 'job': name, 'program': program, 'signaled': signaled,
            'cooperative': cooperative, 'message': message}


@contextmanager
def job_execution(root: Path, name: str, program: str, *, worker=None):
    _safe_name(name)
    check_stop(root, name)
    owner = root / 'results' / '.running' / '.owners' / f'{name}.json'
    identity = process_identity(os.getpid()) or {'pid': os.getpid()}
    _write(owner, {'job': name, 'program': program, **identity})
    original_http = request.urlopen
    original_dns = worker._resolve_host_ips if worker else None
    original_tcp = worker._tcp_port_open if worker else None

    def checked_http(*args, **kwargs):
        check_stop(root, name)
        if original_http is _DEFAULT_URLOPEN and args and getattr(args[0], '_vhost_connect_ip', None):
            class StopAwareRedirect(VhostRedirectHandler):
                def redirect_request(self, *values, **options):
                    check_stop(root, name)
                    return super().redirect_request(*values, **options)
            return vhost_opener(StopAwareRedirect()).open(*args, **kwargs)
        return original_http(*args, **kwargs)

    def checked_dns(*args, **kwargs):
        check_stop(root, name)
        return original_dns(*args, **kwargs)

    def checked_tcp(*args, **kwargs):
        check_stop(root, name)
        return original_tcp(*args, **kwargs)

    request.urlopen = checked_http
    if worker:
        worker._resolve_host_ips = checked_dns
        worker._tcp_port_open = checked_tcp
    try:
        yield
        check_stop(root, name)
    finally:
        request.urlopen = original_http
        if worker:
            worker._resolve_host_ips = original_dns
            worker._tcp_port_open = original_tcp
        owner.unlink(missing_ok=True)