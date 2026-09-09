import base64
import json
import os
import unittest
from unittest.mock import patch
import manager


class PoolTests(unittest.TestCase):
    def test_only_queued_jobs_with_the_pool_label_create_demand(self):
        self.assertTrue(manager.wanted_job({'id': 1, 'status': 'queued', 'labels': [manager.LABEL]}))
        self.assertFalse(manager.wanted_job({'id': 2, 'status': 'in_progress', 'labels': [manager.LABEL]}))
        self.assertFalse(manager.wanted_job({'id': 3, 'status': 'queued', 'labels': ['ubuntu-latest']}))

    def test_pull_requests_do_not_launch_workers(self):
        with patch.object(manager, 'github', return_value={'workflow_runs': [
            {'id': 1, 'event': 'pull_request', 'path': '.github/workflows/ci.yml'},
            {'id': 2, 'event': 'push', 'path': '.github/workflows/ci.yml'}
        ]}) as api:
            self.assertEqual(manager.demand(), 0)
            self.assertEqual(api.call_count, 2)

    def test_worker_gets_one_job_config_and_never_admin_credentials(self):
        with patch.dict(os.environ, {'RUNNER_IMAGE': 'registry.fly.io/example@sha256:' + 'a' * 64,
                                     'GITHUB_TOKEN': 'admin-github', 'FLY_API_TOKEN': 'admin-fly'}), \
             patch.object(manager, 'github', return_value={'runner': {'id': 42}, 'encoded_jit_config': 'one-job'}) as gh, \
             patch.object(manager, 'fly', return_value={'id': 'machine'}) as fly:
            manager.launch({'id': 'vol_a', 'region': 'iad'})
            body = fly.call_args.args[2]
            serialized = json.dumps(body)
            self.assertNotIn('admin-github', serialized)
            self.assertNotIn('admin-fly', serialized)
            self.assertEqual(base64.b64decode(body['config']['files'][0]['raw_value']), b'one-job')
            self.assertEqual(body['config']['mounts'], [{'volume': 'vol_a', 'path': '/data'}])
            self.assertEqual(body['config']['restart'], {'policy': 'no'})

    def test_failed_machine_creation_removes_orphan_runner(self):
        with patch.dict(os.environ, {'RUNNER_IMAGE': 'image'}), \
             patch.object(manager, 'github', return_value={'runner': {'id': 42}, 'encoded_jit_config': 'one-job'}) as gh, \
             patch.object(manager, 'fly', side_effect=RuntimeError('capacity')):
            with self.assertRaises(RuntimeError):
                manager.launch({'id': 'vol_a', 'region': 'iad'})
            gh.assert_called_with('actions/runners/42', 'DELETE')

    def test_pool_cannot_exceed_two_volumes(self):
        with patch.dict(os.environ, {'RUNNER_VOLUMES': json.dumps([{'id': str(i)} for i in range(3)])}):
            with self.assertRaises(ValueError):
                manager.reconcile()

    def test_an_active_workers_volume_cannot_be_assigned_twice(self):
        active = {'id': 'm1', 'state': 'started', 'config': {
            'metadata': {'managed_by': 'nucleus-fly-runner', 'github_runner_id': '1'},
            'mounts': [{'volume': 'vol_a'}]}}
        volumes = [{'id': 'vol_a', 'region': 'iad'}, {'id': 'vol_b', 'region': 'iad'}]
        with patch.dict(os.environ, {'RUNNER_VOLUMES': json.dumps(volumes)}), \
             patch.object(manager, 'fly', return_value=[active]), \
             patch.object(manager, 'github', return_value={'runners': [
                 {'id': 1, 'name': 'nucleus-fly-1', 'status': 'online', 'busy': True}]}), \
             patch.object(manager, 'demand', return_value=20), \
             patch.object(manager, 'launch') as launch:
            manager.reconcile()
            launch.assert_called_once_with(volumes[1])


if __name__ == '__main__':
    unittest.main()
