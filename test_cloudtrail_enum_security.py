"""Offline behavior tests; no credentials or AWS calls."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest

try:
    from botocore.exceptions import ClientError
except ImportError:
    # Isolated exception stand-ins permit offline tests without installing Pacu.
    exceptions = types.ModuleType('botocore.exceptions')
    class ClientError(Exception):
        def __init__(self, response, operation):
            self.response = response
    exceptions.ClientError = ClientError
    exceptions.BotoCoreError = type('BotoCoreError', (Exception,), {})
    sys.modules['botocore'] = types.ModuleType('botocore')
    sys.modules['botocore.exceptions'] = exceptions

spec = importlib.util.spec_from_file_location('security', Path(__file__).parent / 'cloudtrail__enum_security/main.py')
security = importlib.util.module_from_spec(spec)
spec.loader.exec_module(security)


class Pacu:
    database = None
    def __init__(self):
        self.CloudTrail = {'Trails': [{'Name': 'preserved'}]}
        self.calls = []
    def get_active_session(self):
        return self
    def get_regions(self, service):
        return ['us-east-1']
    def key_info(self):
        return {'Permissions': {'Allow': {'cloudtrail:*': {'Resources': ['*'], 'Conditions': []}}}}
    def print(self, message):
        pass
    def update(self, database, **fields):
        self.CloudTrail = fields['CloudTrail']
    def get_boto3_client(self, service, region):
        parent = self
        class Client:
            def __getattr__(self, operation):
                def call(**params):
                    parent.calls.append((service, operation, params))
                    if operation == 'get_caller_identity':
                        return {'Arn': 'arn:aws:iam::123456789012:user/auditor'}
                    if operation == 'describe_trails':
                        return {'trailList': [{'Name': 'audit', 'HomeRegion': 'us-east-1',
                                'TrailARN': 'arn:aws:cloudtrail:us-east-1:123456789012:trail/audit'}]}
                    if operation == 'simulate_principal_policy':
                        return {'EvaluationResults': [{'EvalActionName': params['ActionNames'][0],
                                'EvalResourceName': params['ResourceArns'][0], 'EvalDecision': 'allowed'}]}
                    return {}
                return call
        return Client()


class Tests(unittest.TestCase):
    def test_default_main_simulates_and_preserves_db(self):
        pacu = Pacu()
        result = security.main([], pacu)
        self.assertEqual(pacu.CloudTrail['Trails'], [{'Name': 'preserved'}])
        decisions = result['DangerousPermissions']['Results']
        self.assertEqual(sum(r['SimulationDecision'] == 'allowed' for r in decisions), 5)
        self.assertTrue(all(r['LiveExecution'] == 'NOT TESTED' for r in decisions))
        self.assertTrue(all(op in security.READS[service] for service, op, _ in pacu.calls))
        self.assertIn('Security Summary', security.summary(result, pacu))

    def test_missing_context_never_reports_allow(self):
        class Reader:
            def read(self, service, region, operation, **params):
                if operation != 'simulate_principal_policy':
                    return {'Status': 'OK', 'Data': {}}
                return {'Status': 'OK', 'Data': {'EvaluationResults': [
                    {'EvalActionName': 'cloudtrail:StopLogging', 'EvalResourceName': 'trail-arn',
                     'EvalDecision': 'allowed', 'MissingContextValues': ['aws:SourceIp']}]}}
        result = security.simulate(Reader(), {'Status': 'OK', 'Arn': 'user-arn'},
                                   [{'Action': 'cloudtrail:StopLogging', 'Resource': 'trail-arn'}],
                                   [], security.cached_evidence(Pacu()), True)
        self.assertEqual(result['Results'][0]['SimulationDecision'], 'UNKNOWN')
        self.assertEqual(result['Results'][0]['MissingContextValues'], ['aws:SourceIp'])

    def test_no_simulate_makes_no_iam_or_sts_calls(self):
        pacu = Pacu()
        security.main(['--no-simulate'], pacu)
        self.assertFalse(any(s in ('iam', 'sts') for s, _, _ in pacu.calls))

    def test_deny_continues_and_keeps_partial_pages(self):
        pacu = Pacu()
        class Client:
            def describe_metric_filters(self, **params):
                if params.get('nextToken'):
                    raise ClientError({'Error': {'Code': 'AccessDenied'}}, 'DescribeMetricFilters')
                return {'metricFilters': [{'filterName': 'first'}], 'nextToken': 'second'}
        pacu.get_boto3_client = lambda *args: Client()
        response = security.Reader(pacu).read('logs', 'us-east-1', 'describe_metric_filters',
                                              keys=['metricFilters'], token='nextToken', logGroupName='audit')
        self.assertEqual(response['Status'], 'ACCESS DENIED')
        self.assertEqual(len(response['Data']['metricFilters']), 1)

    def test_assumed_role_uses_canonical_role_arn(self):
        class Reader:
            def read(self, service, region, operation, **params):
                if service == 'sts':
                    return {'Status': 'OK', 'Data': {'Arn': 'arn:aws:sts::123456789012:assumed-role/audit/session'}}
                return {'Status': 'OK', 'Data': {'Role': {'Arn': 'arn:aws:iam::123456789012:role/team/audit'}}}
        result = security.resolve_principal(Reader())
        self.assertEqual(result['Arn'], 'arn:aws:iam::123456789012:role/team/audit')
        self.assertIn('session', result['Scope'])

    def test_mutations_blocked(self):
        with self.assertRaises(ValueError):
            security.Reader(Pacu()).read('cloudtrail', None, 'stop_logging', Name='audit')


if __name__ == '__main__':
    unittest.main()
