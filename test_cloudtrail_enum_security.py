"""Offline checks: run with python -m unittest discover -s outputs -p 'test_*.py'."""
import importlib.util
import json
from pathlib import Path
import unittest

import botocore.session
from botocore.exceptions import ClientError
from botocore.validate import validate_parameters
from botocore import xform_name

spec = importlib.util.spec_from_file_location('security', Path(__file__).parent / 'cloudtrail__enum_security/main.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FakeClient:
    def __init__(self, service, pacu):
        self.service, self.pacu = service, pacu
        self.model = botocore.session.get_session().get_service_model(service)

    def __getattr__(self, operation):
        operation_name = next(n for n in self.model.operation_names if xform_name(n) == operation)
        shape = self.model.operation_model(operation_name).input_shape

        def call(**params):
            validate_parameters(params, shape)
            self.pacu.calls.append((self.service, operation, params))
            if operation == 'describe_trails':
                trail = {'Name': 'audit', 'TrailARN': 'arn:aws:cloudtrail:us-east-1:123456789012:trail/audit',
                         'HomeRegion': 'us-east-1', 'IsMultiRegionTrail': True, 'IsOrganizationTrail': True,
                         'LogFileValidationEnabled': True, 'S3BucketName': 'audit-bucket',
                         'KmsKeyId': 'arn:aws:kms:us-east-1:123456789012:key/test',
                         'CloudWatchLogsLogGroupArn': 'arn:aws:logs:us-west-2:123456789012:log-group:audit:*',
                         'SnsTopicARN': 'arn:aws:sns:us-east-1:123456789012:audit'}
                return {'trailList': [trail]}
            if operation == 'get_bucket_policy':
                raise ClientError({'Error': {'Code': 'AccessDenied'}}, operation_name)
            if operation == 'get_bucket_location':
                return {'LocationConstraint': None}
            if operation == 'get_trail_status':
                return {'IsLogging': False}
            if operation == 'get_bucket_encryption':
                return {'ServerSideEncryptionConfiguration': {'Rules': [{'ApplyServerSideEncryptionByDefault':
                        {'KMSMasterKeyID': 'test', 'SSEAlgorithm': 'aws:kms'}}]}}
            if operation == 'get_event_selectors':
                return {'EventSelectors': [{'ReadWriteType': 'All', 'IncludeManagementEvents': True,
                                           'DataResources': []}], 'AdvancedEventSelectors': []}
            if operation == 'describe_metric_filters':
                if 'nextToken' not in params:
                    return {'metricFilters': [], 'nextToken': 'page2'}
                return {'metricFilters': [{'metricTransformations': [{'metricNamespace': 'Audit', 'metricName': 'Changes'}]}]}
            if operation == 'describe_alarms':
                return {'MetricAlarms': [{'Namespace': 'Audit', 'MetricName': 'Changes',
                         'AlarmActions': ['arn:aws:sns:us-west-2:123456789012:alarm']}], 'CompositeAlarms': []}
            if operation == 'list_event_buses':
                return {'EventBuses': [{'Name': 'default'}]}
            if operation == 'list_rules':
                return {'Rules': [{'Name': 'audit', 'State': 'ENABLED', 'EventPattern': '{}'}]}
            if operation == 'list_targets_by_rule':
                return {'Targets': [{'Arn': 'arn:aws:sns:us-east-1:123456789012:events'}]}
            return {}
        return call


class FakeSession:
    CloudTrail = {'Trails': [{'Name': 'existing'}], 'Other': {'keep': True}}

    def update(self, database, **kwargs):
        self.CloudTrail = kwargs['CloudTrail']
        json.dumps(self.CloudTrail)


class FakePacu:
    def __init__(self):
        self.session, self.calls, self.database = FakeSession(), [], None

    def get_active_session(self):
        return self.session

    def get_regions(self, service):
        return ['us-east-1', 'us-west-2']

    def get_boto3_client(self, service, region):
        return FakeClient(service, self)

    def key_info(self):
        return {'Permissions': {'Allow': {'cloudtrail:*': {'Resources': ['*'], 'Conditions': []}},
                                'Deny': {'cloudtrail:DeleteTrail': {'Resources': ['*'], 'Conditions': []}}}}

    def print(self, message):
        pass


class Checks(unittest.TestCase):
    def test_offline_end_to_end_and_aws_parameter_shapes(self):
        pacu = FakePacu()
        data = module.main([], pacu)
        self.assertEqual(len(data['Trails']), 1)
        self.assertEqual(data['Trails'][0]['Storage']['Policy']['Status'], 'ACCESS DENIED')
        self.assertEqual(data['Trails'][0]['Storage']['Versioning']['Status'], 'OK')
        self.assertEqual(len(data['Trails'][0]['Detection']['CandidateMetricAlarms']), 1)
        self.assertEqual(len(data['SNS']), 3)
        self.assertEqual(pacu.session.CloudTrail['Other'], {'keep': True})
        self.assertEqual(pacu.session.CloudTrail['Trails'], [{'Name': 'existing'}])
        self.assertIn('not currently logging', module.summary(data, pacu))
        self.assertTrue(all(op in module.READS[service] for service, op, _ in pacu.calls))
        self.assertTrue(all(p['EffectivePermission'] == 'UNKNOWN' for p in data['DangerousPermissions']))
        self.assertEqual(data['DangerousPermissions'][1]['PolicyEvidence'], 'ALLOW_AND_DENY')

    def test_partial_pagination_keeps_data_and_denial(self):
        pacu = FakePacu()
        class Partial:
            def describe_metric_filters(self, **params):
                if params.get('nextToken'):
                    raise ClientError({'Error': {'Code': 'AccessDeniedException'}}, 'DescribeMetricFilters')
                return {'metricFilters': [{'filterName': 'first'}], 'nextToken': 'second'}
        pacu.get_boto3_client = lambda *args: Partial()
        response = module.Reader(pacu).read('logs', 'us-east-1', 'describe_metric_filters',
                                            keys=['metricFilters'], token='nextToken', logGroupName='audit')
        self.assertEqual(response['Status'], 'ACCESS DENIED')
        self.assertEqual(len(response['Data']['metricFilters']), 1)

    def test_no_permission_data_is_unknown(self):
        pacu = FakePacu()
        pacu.key_info = lambda: False
        self.assertTrue(all(p['PolicyEvidence'] == 'UNKNOWN' for p in module.permissions(pacu)))

    def test_mutation_guard(self):
        with self.assertRaises(AssertionError):
            module.Reader(FakePacu()).read('cloudtrail', 'us-east-1', 'stop_logging', Name='audit')


if __name__ == '__main__':
    unittest.main()
