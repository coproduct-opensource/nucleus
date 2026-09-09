"""A warm, bounded pool of Fly Machines that run this repository's GitHub Actions jobs.

Why a pool and not one Machine per job: a Machine that finished a job and STOPPED keeps its
root filesystem on its host, so starting it again takes about a second and pulls nothing.
Creating a Machine pulls the image every time (tens of seconds for a Rust image) and, for a
build worker, would separate the job from its cache volume. So every pool is a fixed set of
Machines that cycle stopped -> started -> stopped, one job per start, a fresh one-job JIT
runner configuration written into the Machine before each start.

Administrative credentials (a GitHub token that can register runners, a Fly token for the
worker app) live in this manager and never in a worker: a worker receives exactly one JIT
configuration, good for one job, and nothing else.

Configuration (environment):
  GITHUB_TOKEN, FLY_API_TOKEN      the administrative credentials (secrets)
  RUNNER_IMAGE                     the worker image, pinned by digest
  GITHUB_REPO                      owner/name (default coproduct-opensource/nucleus)
  RUNNER_APP                       the Fly app the workers live in
  POOLS                            JSON: [{label, guest, size, standby, volumes?, env?}]
     label    the runs-on label (also the runner name prefix)
     guest    {"cpu_kind": "performance", "cpus": 8, "memory_mb": 32768}
     size     how many Machines the pool holds (created on first reconcile)
     standby  how many stopped Machines to keep warm regardless of demand (the rest are
              destroyed after IDLE_MINUTES stopped, and re-created when demand returns)
     volumes  optional list of Fly volume ids, one per Machine, mounted at /data (caches)
     env      optional extra environment for the worker (e.g. CARGO_BUILD_JOBS)
  POLL_SECONDS                     reconcile period (default 20)
  IDLE_MINUTES                     minutes a stopped Machine above `standby` lives (default 30)
  LOOKBACK_RUNS                    how many recent runs to scan for queued jobs (default 30)
"""
import base64
import json
import os
import time
import urllib.error
import urllib.request

REPO = os.environ.get('GITHUB_REPO', 'coproduct-opensource/nucleus')
APP = os.environ.get('RUNNER_APP', 'nucleus-fly-build')
MANAGED = 'nucleus-fly-runner'
POLL_SECONDS = int(os.environ.get('POLL_SECONDS', '20'))
IDLE_MINUTES = int(os.environ.get('IDLE_MINUTES', '30'))
LOOKBACK_RUNS = int(os.environ.get('LOOKBACK_RUNS', '30'))
JIT_PATH = '/run/runner-jit'

# Conditional requests: GitHub answers an unchanged resource with 304 and does not count it
# against the rate limit, which is what lets the manager poll every few seconds.
_etags = {}


def request(base, path, token, method='GET', body=None, conditional=False):
    data = None if body is None else json.dumps(body).encode()
    headers = {
        'Authorization': f'Bearer {token}', 'Content-Type': 'application/json',
        'Accept': 'application/json', 'User-Agent': 'nucleus-fly-runner-manager',
    }
    key = base + path
    if conditional and key in _etags:
        headers['If-None-Match'] = _etags[key][0]
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            content = response.read()
            parsed = json.loads(content) if content else None
            if conditional and response.headers.get('ETag'):
                _etags[key] = (response.headers['ETag'], parsed)
            return parsed
    except urllib.error.HTTPError as error:
        if error.code == 304 and conditional and key in _etags:
            return _etags[key][1]
        # Never print API bodies: JIT responses and Machine configs carry credentials.
        raise RuntimeError(f'{method} {path.split("?")[0]}: HTTP {error.code}') from None


def github(path, method='GET', body=None, conditional=False):
    return request('https://api.github.com', f'/repos/{REPO}/' + path,
                   os.environ['GITHUB_TOKEN'], method, body, conditional)


def fly(path, method='GET', body=None):
    return request('https://api.machines.dev/v1', f'/apps/{APP}/' + path,
                   os.environ['FLY_API_TOKEN'], method, body)


def pools():
    out = json.loads(os.environ['POOLS'])
    if not out:
        raise ValueError('POOLS is empty')
    for p in out:
        for k in ('label', 'guest', 'size', 'standby'):
            if k not in p:
                raise ValueError(f'pool without {k}')
        if not 0 <= p['standby'] <= p['size']:
            raise ValueError(f'{p["label"]}: standby must be within 0..size')
        vols = p.get('volumes') or []
        if vols and len(vols) != p['size']:
            raise ValueError(f'{p["label"]}: one volume per Machine, or none')
        if len(set(vols)) != len(vols):
            raise ValueError(f'{p["label"]}: volumes must be distinct')
    if len({p['label'] for p in out}) != len(out):
        raise ValueError('pool labels must be distinct')
    return out


# ── Demand: queued jobs per label, from the most recent runs, cheaply ───────────────────────

def wanted(job, label):
    return job['status'] == 'queued' and label in job.get('labels', [])


def demand(labels):
    """Queued jobs per label across every event and workflow (a pull request's clippy is as
    real as a merge group's). Only the most recent LOOKBACK_RUNS runs that are queued or in
    progress are scanned, with conditional requests, so a tick costs a handful of calls."""
    counts = {label: set() for label in labels}
    runs = []
    for status in ('queued', 'in_progress'):
        page = github(f'actions/runs?status={status}&per_page={LOOKBACK_RUNS}', conditional=True)
        runs.extend(page.get('workflow_runs', []))
    runs.sort(key=lambda r: r.get('created_at', ''), reverse=True)
    for run in runs[:LOOKBACK_RUNS]:
        page = github(f'actions/runs/{run["id"]}/jobs?filter=latest&per_page=100', conditional=True)
        for job in page.get('jobs', []):
            for label in labels:
                if wanted(job, label):
                    counts[label].add(job['id'])
    return {label: len(ids) for label, ids in counts.items()}


# ── Machines: a fixed set per pool, cycling stopped -> started -> stopped ────────────────────

def machine_name(label, index):
    return f'{label}-{index}'


def pool_of(machine):
    return machine.get('config', {}).get('metadata', {}).get('pool')


def managed(machines):
    return [m for m in machines if m.get('config', {}).get('metadata', {}).get('managed_by') == MANAGED]


def jit_config(label, name):
    """One job's runner registration: GitHub's JIT configuration, which registers a runner
    that is removed the moment its single job completes."""
    return github('actions/runners/generate-jitconfig', 'POST', {
        'name': name, 'runner_group_id': 1,
        'labels': ['self-hosted', 'Linux', 'X64', label], 'work_folder': '_work',
    })


def base_config(pool, index):
    cfg = {
        'image': os.environ['RUNNER_IMAGE'],
        'guest': pool['guest'],
        'env': dict(pool.get('env', {})),
        'init': {},
        'restart': {'policy': 'no'},
        'auto_destroy': False,
        'metadata': {'managed_by': MANAGED, 'pool': pool['label'], 'index': str(index)},
    }
    if pool.get('volumes'):
        cfg['mounts'] = [{'volume': pool['volumes'][index], 'path': '/data'}]
    return cfg


def create(pool, index, region):
    """Create a Machine stopped, then start it once with no job so it pulls its image and
    exits: from then on every start is warm."""
    name = machine_name(pool['label'], index)
    machine = fly('machines', 'POST', {
        'name': name, 'region': region, 'skip_launch': True, 'config': base_config(pool, index),
    })
    fly(f'machines/{machine["id"]}/start', 'POST')
    print(f'{pool["label"]}: created {name} ({machine["id"]}), warming', flush=True)
    return machine


def launch(pool, machine):
    """Give a stopped Machine one job's JIT configuration and start it."""
    name = machine['name'] + '-' + str(int(time.time()))
    jit = jit_config(pool['label'], name)
    cfg = dict(machine['config'])
    cfg['files'] = [{'guest_path': JIT_PATH,
                     'raw_value': base64.b64encode(jit['encoded_jit_config'].encode()).decode()}]
    cfg['metadata'] = dict(cfg.get('metadata', {}), github_runner_id=str(jit['runner']['id']))
    try:
        fly(f'machines/{machine["id"]}', 'POST', {'config': cfg})
        fly(f'machines/{machine["id"]}/start', 'POST')
    except Exception:
        github(f'actions/runners/{jit["runner"]["id"]}', 'DELETE')
        raise
    print(f'{pool["label"]}: started {machine["name"]} as runner {jit["runner"]["id"]}', flush=True)


def stopped_since(machine):
    """Seconds since the Machine stopped, from its last event; 0 when unknown."""
    for event in machine.get('events', []):
        if event.get('type') == 'exit' or event.get('status') == 'stopped':
            ts = event.get('timestamp', 0)
            return max(0.0, time.time() - ts / 1000.0)
    return 0.0


def orphaned_runners(prefixes):
    """Runners we registered whose Machine is gone (offline and not busy): GitHub removes a
    JIT runner after its job, so an offline one only exists if the job never ran."""
    runners = github('actions/runners?per_page=100').get('runners', [])
    return [r for r in runners
            if any(r['name'].startswith(p + '-') for p in prefixes)
            and r['status'] == 'offline' and not r['busy']]


def reconcile(region='iad'):
    cfg = pools()
    machines = managed(fly('machines'))
    by_pool = {p['label']: [m for m in machines if pool_of(m) == p['label']] for p in cfg}
    need = demand([p['label'] for p in cfg])
    runners = github('actions/runners?per_page=100').get('runners', [])
    for pool in cfg:
        label = pool['label']
        mine = by_pool[label]
        # Machines already serving a job or about to: started, or stopped with a runner that
        # is still registered and idle (it will pick a job up any second).
        online_idle = {r['name'] for r in runners
                       if r['name'].startswith(label + '-') and r['status'] == 'online' and not r['busy']}
        started = [m for m in mine if m['state'] in ('started', 'starting', 'created')]
        stopped = [m for m in mine if m['state'] == 'stopped']
        needed = max(0, need[label] - len(online_idle) - len([m for m in started]))
        # Start warm Machines first; create up to `size` when the warm ones are all busy.
        for machine in stopped:
            if needed == 0:
                break
            launch(pool, machine)
            needed -= 1
        existing = {m['name'] for m in mine}
        for index in range(pool['size']):
            if needed == 0:
                break
            name = machine_name(label, index)
            if name not in existing:
                create(pool, index, region)
                needed -= 1
        # Keep `standby` warm Machines; retire the rest after IDLE_MINUTES stopped.
        idle = sorted(stopped, key=stopped_since, reverse=True)
        surplus = max(0, len(idle) - pool['standby'])
        for machine in idle[:surplus]:
            if stopped_since(machine) > IDLE_MINUTES * 60:
                fly(f'machines/{machine["id"]}?force=true', 'DELETE')
                print(f'{label}: retired idle {machine["name"]}', flush=True)
        # Warm up to `standby` even with no demand, so the first job of the day is warm too.
        warm_or_busy = len(mine)
        for index in range(pool['size']):
            if warm_or_busy >= pool['standby']:
                break
            name = machine_name(label, index)
            if name not in existing:
                create(pool, index, region)
                warm_or_busy += 1
    for runner in orphaned_runners([p['label'] for p in cfg]):
        github(f'actions/runners/{runner["id"]}', 'DELETE')
        print(f'removed orphaned runner {runner["name"]}', flush=True)
    return need


if __name__ == '__main__':
    if '@sha256:' not in os.environ['RUNNER_IMAGE']:
        raise SystemExit('RUNNER_IMAGE must be pinned by digest')
    pools()
    while True:
        try:
            reconcile(os.environ.get('FLY_REGION', 'iad'))
        except Exception as error:
            print(f'reconcile failed: {type(error).__name__}: {error}', flush=True)
        time.sleep(POLL_SECONDS)
