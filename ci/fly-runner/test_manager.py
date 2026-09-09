import base64
import json
import os
import time
import unittest
from unittest.mock import patch
import manager

BUILD = {'label': 'nucleus-fly-build', 'guest': {'cpu_kind': 'performance', 'cpus': 8, 'memory_mb': 32768},
         'size': 2, 'standby': 1, 'volumes': ['vol_a', 'vol_b'], 'env': {'CARGO_BUILD_JOBS': '8'}}
GATE = {'label': 'nucleus-fly-gate', 'guest': {'cpu_kind': 'shared', 'cpus': 2, 'memory_mb': 4096},
        'size': 3, 'standby': 1}


def machine(name, state, pool, index='0', mounts=None, stopped_ago=0):
    return {'id': 'm-' + name, 'name': name, 'state': state,
            'config': {'image': 'img', 'metadata': {'managed_by': manager.MANAGED, 'pool': pool, 'index': index},
                       'mounts': mounts or []},
            'events': [{'type': 'exit', 'status': 'stopped', 'timestamp': (time.time() - stopped_ago) * 1000}]}


class PoolConfig(unittest.TestCase):
    def test_pools_are_validated(self):
        with patch.dict(os.environ, {'POOLS': json.dumps([BUILD, GATE])}):
            self.assertEqual([p['label'] for p in manager.pools()], ['nucleus-fly-build', 'nucleus-fly-gate'])
        for bad in ([], [dict(BUILD, standby=3)], [dict(BUILD, volumes=['vol_a'])],
                    [dict(BUILD, volumes=['vol_a', 'vol_a'])], [BUILD, BUILD], [{'label': 'x'}]):
            with patch.dict(os.environ, {'POOLS': json.dumps(bad)}):
                with self.assertRaises(ValueError, msg=json.dumps(bad)):
                    manager.pools()


class Demand(unittest.TestCase):
    def test_queued_jobs_with_a_pool_label_count_whatever_the_event(self):
        runs = {'workflow_runs': [
            {'id': 1, 'event': 'pull_request', 'created_at': '2'},
            {'id': 2, 'event': 'merge_group', 'created_at': '1'},
        ]}
        jobs = {
            'actions/runs/1/jobs?filter=latest&per_page=100': {'jobs': [
                {'id': 10, 'status': 'queued', 'labels': ['self-hosted', 'nucleus-fly-build']},
                {'id': 11, 'status': 'in_progress', 'labels': ['nucleus-fly-build']},
                {'id': 12, 'status': 'queued', 'labels': ['ubuntu-latest']},
                {'id': 13, 'status': 'queued', 'labels': ['nucleus-fly-gate']},
            ]},
            'actions/runs/2/jobs?filter=latest&per_page=100': {'jobs': [
                {'id': 20, 'status': 'queued', 'labels': ['nucleus-fly-build']},
            ]},
        }

        def fake(path, method='GET', body=None, conditional=False):
            self.assertTrue(conditional, path)
            if path.startswith('actions/runs?'):
                return runs
            return jobs[path]
        with patch.object(manager, 'github', side_effect=fake):
            self.assertEqual(manager.demand(['nucleus-fly-build', 'nucleus-fly-gate']),
                             {'nucleus-fly-build': 2, 'nucleus-fly-gate': 1})

    def test_a_304_reuses_the_cached_body_and_costs_nothing(self):
        import urllib.error
        manager._etags.clear()

        class Resp:
            headers = {'ETag': 'W/"abc"'}

            def __init__(self, body):
                self.body = body

            def read(self):
                return self.body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        calls = []

        def urlopen(req, timeout):
            calls.append(req.headers.get('If-none-match'))
            if req.headers.get('If-none-match') == 'W/"abc"':
                raise urllib.error.HTTPError(req.full_url, 304, 'not modified', {}, None)
            return Resp(b'{"x": 1}')
        with patch.object(manager.urllib.request, 'urlopen', side_effect=urlopen):
            self.assertEqual(manager.request('https://h', '/p', 't', conditional=True), {'x': 1})
            self.assertEqual(manager.request('https://h', '/p', 't', conditional=True), {'x': 1})
        self.assertEqual(calls, [None, 'W/"abc"'])


class Workers(unittest.TestCase):
    def test_a_launch_writes_one_job_config_and_never_admin_credentials(self):
        stopped = machine('nucleus-fly-build-0', 'stopped', 'nucleus-fly-build', mounts=[{'volume': 'vol_a', 'path': '/data'}])
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'admin-github', 'FLY_API_TOKEN': 'admin-fly'}), \
             patch.object(manager, 'github', return_value={'runner': {'id': 42}, 'encoded_jit_config': 'one-job'}) as gh, \
             patch.object(manager, 'fly', return_value={}) as fly:
            manager.launch(BUILD, stopped)
        update, start = fly.call_args_list
        self.assertEqual(update.args[0], 'machines/m-nucleus-fly-build-0')
        cfg = update.args[2]['config']
        serialized = json.dumps(cfg)
        self.assertNotIn('admin-github', serialized)
        self.assertNotIn('admin-fly', serialized)
        self.assertEqual(base64.b64decode(cfg['files'][0]['raw_value']), b'one-job')
        self.assertEqual(cfg['files'][0]['guest_path'], manager.JIT_PATH)
        self.assertEqual(cfg['metadata']['github_runner_id'], '42')
        self.assertEqual(cfg['mounts'], [{'volume': 'vol_a', 'path': '/data'}])
        self.assertEqual(start.args[0], 'machines/m-nucleus-fly-build-0/start')
        self.assertEqual(gh.call_args.args[2]['labels'], ['self-hosted', 'Linux', 'X64', 'nucleus-fly-build'])

    def test_a_failed_start_removes_the_orphan_runner(self):
        with patch.object(manager, 'github', return_value={'runner': {'id': 42}, 'encoded_jit_config': 'j'}) as gh, \
             patch.object(manager, 'fly', side_effect=RuntimeError('capacity')):
            with self.assertRaises(RuntimeError):
                manager.launch(GATE, machine('nucleus-fly-gate-0', 'stopped', 'nucleus-fly-gate'))
            gh.assert_called_with('actions/runners/42', 'DELETE')

    def test_a_created_machine_is_stopped_first_and_warmed_with_a_volume_of_its_own(self):
        with patch.dict(os.environ, {'RUNNER_IMAGE': 'registry.fly.io/x@sha256:' + 'a' * 64}), \
             patch.object(manager, 'fly', return_value={'id': 'm1'}) as fly:
            manager.create(BUILD, 1, 'iad')
        created, started = fly.call_args_list
        body = created.args[2]
        self.assertTrue(body['skip_launch'])
        self.assertEqual(body['name'], 'nucleus-fly-build-1')
        self.assertEqual(body['config']['mounts'], [{'volume': 'vol_b', 'path': '/data'}])
        self.assertEqual(body['config']['restart'], {'policy': 'no'})
        self.assertEqual(body['config']['metadata']['pool'], 'nucleus-fly-build')
        self.assertEqual(body['config']['env'], {'CARGO_BUILD_JOBS': '8'})
        self.assertNotIn('files', body['config'])
        self.assertEqual(started.args[0], 'machines/m1/start')


class Reconcile(unittest.TestCase):
    def run_reconcile(self, machines, runners, need, pools=(BUILD, GATE)):
        with patch.dict(os.environ, {'POOLS': json.dumps(list(pools)), 'RUNNER_IMAGE': 'r@sha256:' + 'a' * 64}), \
             patch.object(manager, 'fly', side_effect=lambda path, method='GET', body=None: machines if path == 'machines' else {'id': 'new'}) as fly, \
             patch.object(manager, 'github', side_effect=lambda path, *a, **k: {'runners': runners} if path.startswith('actions/runners?') else {}), \
             patch.object(manager, 'demand', return_value=need), \
             patch.object(manager, 'launch') as launch, \
             patch.object(manager, 'create') as create:
            manager.reconcile()
        return launch, create, fly

    def test_demand_starts_stopped_machines_before_creating_new_ones(self):
        machines = [machine('nucleus-fly-build-0', 'stopped', 'nucleus-fly-build', '0'),
                    machine('nucleus-fly-gate-0', 'stopped', 'nucleus-fly-gate', '0')]
        launch, create, _ = self.run_reconcile(machines, [], {'nucleus-fly-build': 2, 'nucleus-fly-gate': 0})
        self.assertEqual([c.args[1]['name'] for c in launch.call_args_list], ['nucleus-fly-build-0'])
        self.assertEqual([(c.args[0]['label'], c.args[1]) for c in create.call_args_list], [('nucleus-fly-build', 1)])

    def test_the_pool_never_exceeds_its_size(self):
        machines = [machine('nucleus-fly-build-0', 'started', 'nucleus-fly-build', '0'),
                    machine('nucleus-fly-build-1', 'started', 'nucleus-fly-build', '1')]
        launch, create, _ = self.run_reconcile(machines, [], {'nucleus-fly-build': 20, 'nucleus-fly-gate': 0})
        launch.assert_not_called()
        self.assertEqual([c.args[0]['label'] for c in create.call_args_list], ['nucleus-fly-gate'])

    def test_a_started_machine_and_an_idle_online_runner_each_cover_one_queued_job(self):
        machines = [machine('nucleus-fly-gate-0', 'started', 'nucleus-fly-gate', '0'),
                    machine('nucleus-fly-gate-1', 'stopped', 'nucleus-fly-gate', '1'),
                    machine('nucleus-fly-gate-2', 'stopped', 'nucleus-fly-gate', '2')]
        runners = [{'id': 1, 'name': 'nucleus-fly-gate-0-1', 'status': 'online', 'busy': False}]
        launch, create, _ = self.run_reconcile(machines, runners, {'nucleus-fly-build': 0, 'nucleus-fly-gate': 3},
                                               pools=(GATE,))
        self.assertEqual([c.args[1]['name'] for c in launch.call_args_list], ['nucleus-fly-gate-1'])
        create.assert_not_called()

    def test_standby_is_warmed_without_demand_and_surplus_idle_machines_retire(self):
        machines = [machine('nucleus-fly-gate-0', 'stopped', 'nucleus-fly-gate', '0', stopped_ago=3600),
                    machine('nucleus-fly-gate-1', 'stopped', 'nucleus-fly-gate', '1', stopped_ago=60),
                    machine('nucleus-fly-gate-2', 'stopped', 'nucleus-fly-gate', '2', stopped_ago=7200)]
        launch, create, fly = self.run_reconcile(machines, [], {'nucleus-fly-build': 0, 'nucleus-fly-gate': 0})
        launch.assert_not_called()
        deleted = [c.args[0] for c in fly.call_args_list if c.args[1:2] == ('DELETE',)]
        self.assertEqual(deleted, ['machines/m-nucleus-fly-gate-2?force=true', 'machines/m-nucleus-fly-gate-0?force=true'])
        # The build pool has nothing yet: its standby of one is created cold.
        self.assertEqual([(c.args[0]['label'], c.args[1]) for c in create.call_args_list], [('nucleus-fly-build', 0)])

    def test_orphaned_offline_runners_are_removed_and_busy_ones_are_not(self):
        runners = [{'id': 1, 'name': 'nucleus-fly-gate-0-9', 'status': 'offline', 'busy': False},
                   {'id': 2, 'name': 'nucleus-fly-gate-1-9', 'status': 'online', 'busy': True},
                   {'id': 3, 'name': 'someone-else', 'status': 'offline', 'busy': False}]
        with patch.object(manager, 'github', return_value={'runners': runners}):
            self.assertEqual([r['id'] for r in manager.orphaned_runners(['nucleus-fly-gate'])], [1])


if __name__ == '__main__':
    unittest.main()
