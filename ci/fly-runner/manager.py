"""Bounded, demand-driven Fly pool for nucleus merge jobs.

Administrative credentials live in this separate app, never in worker Machines.
Workers receive only GitHub's one-job JIT configuration and an exclusive cache volume.
"""
import base64
import json
import os
import time
import urllib.error
import urllib.request

REPO = os.environ.get('GITHUB_REPO', 'coproduct-opensource/nucleus')
APP = os.environ.get('RUNNER_APP', 'nucleus-fly-build')
LABEL = os.environ.get('RUNNER_LABEL', 'nucleus-fly-build')
PREFIX = 'nucleus-fly-'


def request(base, path, token, method='GET', body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method, headers={
        'Authorization': f'Bearer {token}', 'Content-Type': 'application/json',
        'Accept': 'application/json', 'User-Agent': 'nucleus-fly-runner-manager',
    })
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            content = response.read()
            return json.loads(content) if content else None
    except urllib.error.HTTPError as error:
        # Never print API bodies: JIT responses and Machine configs carry credentials.
        raise RuntimeError(f'{method} {path.split("?")[0]}: HTTP {error.code}') from None


def github(path, method='GET', body=None):
    return request('https://api.github.com', f'/repos/{REPO}/' + path,
                   os.environ['GITHUB_TOKEN'], method, body)


def fly(path, method='GET', body=None):
    return request('https://api.machines.dev/v1', f'/apps/{APP}/' + path,
                   os.environ['FLY_API_TOKEN'], method, body)


def wanted_job(job):
    return job['status'] == 'queued' and LABEL in job.get('labels', [])


def demand():
    jobs = set()
    for status in ('queued', 'in_progress'):
        runs = github(f'actions/runs?status={status}&per_page=100')['workflow_runs']
        for run in runs:
            if run.get('path', '').split('@')[0] not in ('.github/workflows/ci.yml', '.github/workflows/runner-smoke.yml'):
                continue
            if run['event'] not in ('merge_group', 'workflow_dispatch'):
                continue
            page = 1
            while True:
                batch = github(f'actions/runs/{run["id"]}/jobs?filter=latest&per_page=100&page={page}')['jobs']
                jobs.update(j['id'] for j in batch if wanted_job(j))
                if len(batch) < 100:
                    break
                page += 1
    return len(jobs)


def cleanup(machine):
    fly(f'machines/{machine["id"]}?force=true', 'DELETE')
    runner_id = machine.get('config', {}).get('metadata', {}).get('github_runner_id')
    if runner_id:
        try:
            github(f'actions/runners/{runner_id}', 'DELETE')
        except RuntimeError as error:
            if 'HTTP 404' not in str(error):
                raise
    print(f'retired worker {machine["id"]}', flush=True)


def launch(volume):
    name = PREFIX + volume['id'].removeprefix('vol_') + '-' + str(int(time.time()))
    jit = github('actions/runners/generate-jitconfig', 'POST', {
        'name': name, 'runner_group_id': 1,
        'labels': ['self-hosted', 'Linux', 'X64', LABEL], 'work_folder': '_work',
    })
    try:
        machine = fly('machines', 'POST', {
            'name': name, 'region': volume['region'],
            'config': {
                'image': os.environ['RUNNER_IMAGE'],
                'guest': {'cpu_kind': 'performance', 'cpus': 4, 'memory_mb': 16384},
                'env': {'CARGO_BUILD_JOBS': '4'},
                'init': {}, 'restart': {'policy': 'no'},
                'mounts': [{'volume': volume['id'], 'path': '/data'}],
                'files': [{'guest_path': '/run/runner-jit', 'raw_value': base64.b64encode(jit['encoded_jit_config'].encode()).decode()}],
                'metadata': {'managed_by': 'nucleus-fly-runner', 'github_runner_id': str(jit['runner']['id'])},
            },
        })
    except Exception:
        github(f'actions/runners/{jit["runner"]["id"]}', 'DELETE')
        raise
    print(f'launched worker {machine["id"]} runner={jit["runner"]["id"]}', flush=True)


def reconcile():
    volumes = json.loads(os.environ['RUNNER_VOLUMES'])
    if not 1 <= len(volumes) <= 2 or len({v['id'] for v in volumes}) != len(volumes):
        raise ValueError('configure one or two distinct worker volumes')
    machines = [m for m in fly('machines')
                if m.get('config', {}).get('metadata', {}).get('managed_by') == 'nucleus-fly-runner']
    for machine in machines:
        if machine['state'] in ('stopped', 'destroyed'):
            cleanup(machine)
    active = [m for m in machines if m['state'] not in ('stopped', 'destroyed')]
    # Online runners include busy jobs: reserve a slot for each active Machine.
    runners = github('actions/runners?per_page=100')['runners']
    idle = sum(r['name'].startswith(PREFIX) and r['status'] == 'online' and not r['busy'] for r in runners)
    registered = {str(r['id']) for r in runners if r['status'] == 'online'}
    starting = sum(m.get('config', {}).get('metadata', {}).get('github_runner_id') not in registered for m in active)
    needed = max(0, demand() - idle - starting)
    occupied = {mount['volume'] for m in active for mount in m.get('config', {}).get('mounts', [])}
    for volume in volumes:
        if needed == 0:
            break
        if volume['id'] not in occupied:
            launch(volume)
            needed -= 1


if __name__ == '__main__':
    if '@sha256:' not in os.environ['RUNNER_IMAGE']:
        raise SystemExit('RUNNER_IMAGE must be pinned by digest')
    while True:
        try:
            reconcile()
        except Exception as error:
            print(f'reconcile failed: {type(error).__name__}: {error}', flush=True)
        time.sleep(30)
