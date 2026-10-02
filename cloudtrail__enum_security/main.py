"""Read-only Pacu inventory and resource-scoped IAM policy simulation."""
import argparse
import json
from copy import deepcopy
from datetime import datetime, timezone
from fnmatch import fnmatchcase

from botocore.exceptions import BotoCoreError, ClientError

module_info = {
    'name': 'cloudtrail__enum_security', 'author': 'Pacu community', 'category': 'ENUM',
    'one_liner': 'Enumerate CloudTrail security and simulate dangerous permissions without changes.',
    'description': 'Read-only configuration inventory with automatic resource-scoped IAM simulation. '
                   'Simulation is not proof of live authorization. Denied sections continue independently.',
    'services': ['CloudTrail', 'S3', 'KMS', 'logs', 'monitoring', 'SNS', 'EventBridge', 'IAM', 'STS'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': ['--regions', '--no-simulate', '--context-file'],
}
parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--regions', help='Comma-separated regions; default: session CloudTrail regions.')
parser.add_argument('--no-simulate', action='store_true', help='Use cached policy evidence only.')
parser.add_argument('--context-file', help='Optional JSON list of IAM ContextEntries. Values are operator supplied.')

READS = {
    'cloudtrail': {'describe_trails', 'get_trail_status', 'get_event_selectors', 'get_insight_selectors'},
    's3': {'get_bucket_location', 'get_bucket_policy', 'get_bucket_versioning',
           'get_object_lock_configuration', 'get_bucket_encryption'},
    'kms': {'describe_key', 'get_key_policy', 'get_key_rotation_status'},
    'logs': {'describe_log_groups', 'describe_metric_filters'},
    'cloudwatch': {'describe_alarms'},
    'events': {'list_event_buses', 'list_rules', 'list_targets_by_rule'},
    'sns': {'get_topic_attributes', 'list_subscriptions_by_topic'},
    'sts': {'get_caller_identity'},
    'iam': {'get_role', 'get_context_keys_for_principal_policy', 'simulate_principal_policy'},
}
DANGEROUS = {
    'cloudtrail:StopLogging': 'CRITICAL', 'cloudtrail:DeleteTrail': 'CRITICAL',
    'cloudtrail:UpdateTrail': 'HIGH', 'cloudtrail:PutEventSelectors': 'HIGH',
    'cloudtrail:PutInsightSelectors': 'HIGH', 's3:DeleteObject': 'STORAGE',
    's3:DeleteObjectVersion': 'STORAGE', 'logs:DeleteMetricFilter': 'DETECTION',
    'cloudwatch:DeleteAlarms': 'DETECTION', 'events:DisableRule': 'DETECTION',
}


def clean(value):
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items() if k != 'ResponseMetadata'}
    if isinstance(value, (list, tuple)):
        return [clean(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


class Reader:
    def __init__(self, pacu):
        self.pacu, self.cache = pacu, {}

    def read(self, service, region, operation, keys=None, token=None, **params):
        if operation not in READS.get(service, set()):
            raise ValueError('Mutation or unsupported operation blocked')
        identity = (service, region, operation, json.dumps(params, sort_keys=True))
        if identity in self.cache:
            return deepcopy(self.cache[identity])
        result = {'Status': 'UNKNOWN', 'Data': {k: [] for k in keys or []}}
        try:
            client = self.pacu.get_boto3_client(service, region)
            if client is None:
                raise ValueError('Client unavailable')
            seen = set()
            while True:
                response = clean(getattr(client, operation)(**params))
                if keys is None:
                    result.update(Status='OK', Data=response)
                    break
                for key in keys:
                    result['Data'][key].extend(response.get(key, []))
                next_token = response.get(token) if token else None
                if not next_token:
                    result['Status'] = 'OK'
                    break
                if next_token in seen:
                    raise ValueError('Repeated pagination token')
                seen.add(next_token)
                params[token] = next_token
        except ClientError as error:
            code = error.response.get('Error', {}).get('Code', 'Unknown')
            result['ErrorCode'] = code
            if 'accessdenied' in code.lower() or code in ('UnauthorizedOperation', 'AuthorizationError'):
                result['Status'] = 'ACCESS DENIED'
            elif code in ('NoSuchBucketPolicy', 'ObjectLockConfigurationNotFoundError',
                          'ServerSideEncryptionConfigurationNotFoundError'):
                result['Status'] = 'NOT CONFIGURED'
        except (BotoCoreError, ValueError, AttributeError) as error:
            result['ErrorCode'] = type(error).__name__
        self.cache[identity] = deepcopy(result)
        if result['Status'] in ('UNKNOWN', 'ACCESS DENIED'):
            self.pacu.print('  {}: {}:{} ({})'.format(result['Status'], service, operation, region))
        return result


def arn_region(arn, fallback):
    parts = (arn or '').split(':')
    return parts[3] if len(parts) > 5 and parts[3] else fallback


def key_details(reader, key, region):
    region = arn_region(key, region)
    return {label: reader.read('kms', region, operation, **params)
            for label, operation, params in [
                ('Metadata', 'describe_key', {'KeyId': key}),
                ('Policy', 'get_key_policy', {'KeyId': key, 'PolicyName': 'default'}),
                ('Rotation', 'get_key_rotation_status', {'KeyId': key})]}


def bucket_details(reader, bucket, region):
    location = reader.read('s3', region, 'get_bucket_location', Bucket=bucket)
    if location['Status'] == 'OK':
        region = location['Data'].get('LocationConstraint') or 'us-east-1'
        region = 'eu-west-1' if region == 'EU' else region
    result = {'Bucket': bucket, 'Location': location}
    for label, operation in [('Policy', 'get_bucket_policy'), ('Versioning', 'get_bucket_versioning'),
                             ('ObjectLock', 'get_object_lock_configuration'), ('Encryption', 'get_bucket_encryption')]:
        result[label] = reader.read('s3', region, operation, Bucket=bucket)
    result['KMS'] = []
    for rule in result['Encryption']['Data'].get('ServerSideEncryptionConfiguration', {}).get('Rules', []):
        key = rule.get('ApplyServerSideEncryptionByDefault', {}).get('KMSMasterKeyID')
        if key:
            result['KMS'].append(key_details(reader, key, region))
    return result


def cached_evidence(pacu):
    cached = (pacu.key_info() or {}).get('Permissions') or {}
    return {action: {effect: {pattern: clean(detail) for pattern, detail in (cached.get(effect) or {}).items()
                             if fnmatchcase(action.lower(), pattern.lower())}
                     for effect in ('Allow', 'Deny')} for action in DANGEROUS}


def resolve_principal(reader):
    identity = reader.read('sts', None, 'get_caller_identity')
    if identity['Status'] != 'OK':
        return {'Status': 'UNKNOWN', 'Identity': identity}
    arn = identity['Data'].get('Arn', '')
    if ':iam::' in arn and ':user/' in arn:
        return {'Status': 'OK', 'Arn': arn, 'SessionIdentity': identity, 'Scope': 'IAM user policies'}
    if ':sts::' in arn and ':assumed-role/' in arn:
        role_name = arn.split(':assumed-role/', 1)[1].split('/')[0]
        role = reader.read('iam', None, 'get_role', RoleName=role_name)
        canonical = role['Data'].get('Role', {}).get('Arn')
        if role['Status'] == 'OK' and canonical:
            return {'Status': 'OK', 'Arn': canonical, 'SessionIdentity': identity,
                    'Scope': 'Base IAM role; active STS session restrictions are not reproduced'}
        return {'Status': 'UNKNOWN', 'Identity': identity, 'RoleResolution': role}
    return {'Status': 'UNKNOWN', 'Identity': identity, 'Reason': 'Unsupported principal type'}


def simulate(reader, principal, targets, contexts, evidence, enabled):
    output = []
    context_keys = ({'Status': 'SKIPPED', 'Data': {}} if not enabled or principal['Status'] != 'OK' else
                    reader.read('iam', None, 'get_context_keys_for_principal_policy',
                                PolicySourceArn=principal['Arn']))
    for action, severity in DANGEROUS.items():
        scoped = [t for t in targets if t['Action'] == action]
        if not scoped:
            scoped = [{'Action': action, 'Resource': None, 'Reason': 'No applicable resource discovered'}]
        for target in scoped:
            entry = dict(target, Severity=severity, CachedEvidence=evidence[action],
                         SimulationDecision='UNKNOWN', LiveExecution='NOT TESTED')
            if not enabled:
                entry['Reason'] = 'Simulation disabled'
            elif principal['Status'] != 'OK':
                entry['Reason'] = 'IAM principal could not be resolved'
            elif target['Resource']:
                response = reader.read('iam', None, 'simulate_principal_policy',
                                       keys=['EvaluationResults'], token='Marker',
                                       PolicySourceArn=principal['Arn'], ActionNames=[action],
                                       ResourceArns=[target['Resource']], ContextEntries=contexts)
                entry['Simulation'] = response
                evaluations = response['Data'].get('EvaluationResults', [])
                match = next((e for e in evaluations if e.get('EvalActionName', '').lower() == action.lower()
                              and e.get('EvalResourceName') == target['Resource']), None)
                if response['Status'] == 'OK' and match:
                    missing = set(match.get('MissingContextValues', []))
                    for resource in match.get('ResourceSpecificResults', []):
                        missing.update(resource.get('MissingContextValues', []))
                    entry['MissingContextValues'] = sorted(missing)
                    decision = match.get('EvalDecision')
                    if not missing and decision in ('allowed', 'explicitDeny', 'implicitDeny'):
                        entry['SimulationDecision'] = decision
                    else:
                        entry['Reason'] = 'Missing context or unrecognized evaluation decision'
                else:
                    entry['Reason'] = 'Simulation unavailable or incomplete'
            output.append(entry)
    return {'Principal': principal, 'ContextKeys': context_keys, 'ContextEntries': contexts,
            'Results': output,
            'Limitations': 'Simulation only: resource policies, endpoint policies, session restrictions, '
                           'Object Lock and actual resource state may change live outcomes. '
                           'S3 resources here are hypothetical objects, not existing object/version checks.'}


def main(args, pacu_main):
    args = parser.parse_args(args)
    contexts = []
    if args.context_file:
        with open(args.context_file, encoding='utf-8') as stream:
            contexts = json.load(stream)
        if not isinstance(contexts, list) or any(not isinstance(c, dict) for c in contexts):
            raise ValueError('context-file must contain a JSON list of IAM ContextEntries')
    session = pacu_main.get_active_session()
    reader = Reader(pacu_main)
    regions = list(dict.fromkeys(r.strip() for r in args.regions.split(',') if r.strip())) if args.regions else list(pacu_main.get_regions('cloudtrail') or [])
    data = {'CollectedAt': datetime.now(timezone.utc).isoformat(), 'Regions': regions,
            'Discovery': {}, 'Trails': [], 'EventBridge': {}, 'SNS': {}}
    targets, topics, seen = [], set(), set()

    def target(action, resource, scope):
        item = {'Action': action, 'Resource': resource, 'Scope': scope}
        if resource and item not in targets:
            targets.append(item)

    for region in regions:
        pacu_main.print('Reading CloudTrail in {}...'.format(region))
        response = reader.read('cloudtrail', region, 'describe_trails', includeShadowTrails=True)
        data['Discovery'][region] = response
        for trail in response['Data'].get('trailList', []):
            home = trail.get('HomeRegion', region)
            arn = trail.get('TrailARN')
            identity = arn or (home, trail.get('Name'))
            if identity in seen:
                continue
            seen.add(identity)
            name = arn or trail.get('Name')
            if not name:
                data['Trails'].append({'Configuration': trail, 'Status': 'UNKNOWN'})
                continue
            item = {'Configuration': trail,
                    'Logging': reader.read('cloudtrail', home, 'get_trail_status', Name=name),
                    'EventCoverage': reader.read('cloudtrail', home, 'get_event_selectors', TrailName=name),
                    'Insights': reader.read('cloudtrail', home, 'get_insight_selectors', TrailName=name),
                    'Integrity': {'LogFileValidationEnabled': trail.get('LogFileValidationEnabled', 'UNKNOWN'),
                                  'DigestVerification': 'UNKNOWN: no digest/signature verification performed'}}
            for action in DANGEROUS:
                if action.startswith('cloudtrail:'):
                    target(action, arn, 'Discovered trail ARN')
            if trail.get('S3BucketName'):
                bucket = trail['S3BucketName']
                item['Storage'] = bucket_details(reader, bucket, home)
                partition = arn.split(':')[1] if arn else 'aws'
                prefix = trail.get('S3KeyPrefix', '').strip('/')
                object_key = (prefix + '/' if prefix else '') + 'AWSLogs/pacu-simulation-example'
                for action in ('s3:DeleteObject', 's3:DeleteObjectVersion'):
                    target(action, 'arn:{}:s3:::{}'.format(partition, bucket) + '/' + object_key,
                           'HYPOTHETICAL object under log prefix; no object/version was inspected')
            if trail.get('KmsKeyId'):
                item['KMS'] = key_details(reader, trail['KmsKeyId'], home)
            if trail.get('SnsTopicARN'):
                topics.add(trail['SnsTopicARN'])
            log_arn = trail.get('CloudWatchLogsLogGroupArn')
            item['Detection'] = {'Status': 'NOT CONFIGURED'}
            if log_arn:
                log_region = arn_region(log_arn, home)
                group = log_arn.split(':log-group:', 1)[-1].removesuffix(':*')
                groups = reader.read('logs', log_region, 'describe_log_groups', keys=['logGroups'],
                                     token='nextToken', logGroupNamePrefix=group)
                groups['Data']['logGroups'] = [g for g in groups['Data']['logGroups'] if g.get('logGroupName') == group]
                filters = reader.read('logs', log_region, 'describe_metric_filters', keys=['metricFilters'],
                                      token='nextToken', logGroupName=group)
                alarms = reader.read('cloudwatch', log_region, 'describe_alarms',
                                     keys=['MetricAlarms', 'CompositeAlarms'], token='NextToken',
                                     AlarmTypes=['MetricAlarm', 'CompositeAlarm'])
                metrics = {(m.get('metricNamespace'), m.get('metricName'))
                           for f in filters['Data']['metricFilters'] for m in f.get('metricTransformations', [])}
                candidates = []
                for alarm in alarms['Data']['MetricAlarms']:
                    refs = {(alarm.get('Namespace'), alarm.get('MetricName'))}
                    refs.update((m.get('MetricStat', {}).get('Metric', {}).get('Namespace'),
                                 m.get('MetricStat', {}).get('Metric', {}).get('MetricName'))
                                for m in alarm.get('Metrics', []))
                    if refs & metrics:
                        candidates.append(alarm)
                        target('cloudwatch:DeleteAlarms', alarm.get('AlarmArn'), 'Metric namespace/name candidate')
                        for field in ('AlarmActions', 'OKActions', 'InsufficientDataActions'):
                            topics.update(a for a in alarm.get(field, []) if ':sns:' in a)
                if filters['Data']['metricFilters']:
                    target('logs:DeleteMetricFilter', log_arn, 'Log group containing discovered filters')
                item['Detection'] = {'Status': groups['Status'], 'LogGroups': groups, 'MetricFilters': filters,
                                     'RegionalAlarms': alarms, 'CandidateAlarms': candidates,
                                     'Correlation': 'Namespace/name candidates; dimensions/math/composite linkage not proven'}
            data['Trails'].append(item)
        buses = reader.read('events', region, 'list_event_buses', keys=['EventBuses'], token='NextToken')
        entries = []
        for bus in buses['Data']['EventBuses']:
            rules = reader.read('events', region, 'list_rules', keys=['Rules'], token='NextToken', EventBusName=bus['Name'])
            rule_entries = []
            for rule in rules['Data']['Rules']:
                linked = reader.read('events', region, 'list_targets_by_rule', keys=['Targets'], token='NextToken',
                                     Rule=rule['Name'], EventBusName=bus['Name'])
                rule_entries.append({'Rule': rule, 'Targets': linked})
                target('events:DisableRule', rule.get('Arn'), 'Inventoried rule; CloudTrail pattern applicability unverified')
                topics.update(t['Arn'] for t in linked['Data']['Targets'] if ':sns:' in t.get('Arn', ''))
            entries.append({'Bus': bus, 'Rules': rules, 'Entries': rule_entries})
        data['EventBridge'][region] = {'Buses': buses, 'Entries': entries}
    for topic in sorted(topics):
        topic_region = arn_region(topic, regions[0] if regions else None)
        data['SNS'][topic] = {
            'Attributes': reader.read('sns', topic_region, 'get_topic_attributes', TopicArn=topic),
            'Subscriptions': reader.read('sns', topic_region, 'list_subscriptions_by_topic',
                                         keys=['Subscriptions'], token='NextToken', TopicArn=topic)}
    principal = {'Status': 'SKIPPED'} if args.no_simulate else resolve_principal(reader)
    data['DangerousPermissions'] = simulate(reader, principal, targets, contexts,
                                            cached_evidence(pacu_main), not args.no_simulate)
    stored = deepcopy(session.CloudTrail or {})
    stored['SecurityPosture'] = clean(data)
    session.update(pacu_main.database, CloudTrail=stored)
    return data


def summary(data, pacu_main):
    lines = ['Security Summary', '  Trails observed: {} (coverage may be incomplete)'.format(len(data['Trails']))]
    for item in data['Trails']:
        config = item['Configuration']
        logging = item.get('Logging', {})
        state = logging['Data'].get('IsLogging', 'UNKNOWN') if logging.get('Status') == 'OK' else logging.get('Status', 'UNKNOWN')
        lines.append('  {} | Home={} | MultiRegion={} | Organization={} | Logging={} | Validation={}'.format(
            config.get('Name', 'UNKNOWN'), config.get('HomeRegion', 'UNKNOWN'),
            config.get('IsMultiRegionTrail', 'UNKNOWN'), config.get('IsOrganizationTrail', 'UNKNOWN'),
            state, config.get('LogFileValidationEnabled', 'UNKNOWN')))
        for label in ('EventCoverage', 'Storage', 'Detection'):
            section = item.get(label, {})
            lines.append('    {}: {}'.format(label, section.get('Status', 'See SecurityPosture details' if section else 'UNKNOWN')))
        if state is False:
            lines.append('    FINDING: trail is not logging.')
    permissions = data['DangerousPermissions']
    lines.append('  Permission simulation: {}'.format(permissions['Principal'].get('Scope', permissions['Principal']['Status'])))
    for item in permissions['Results']:
        lines.append('    [{}] {} -> {}: {}'.format(item['Severity'], item['Action'],
                                                   item['Resource'] or 'UNKNOWN RESOURCE', item['SimulationDecision']))
        if item.get('Reason') or item.get('MissingContextValues'):
            lines.append('      {}'.format(item.get('Reason', '') + ' ' + str(item.get('MissingContextValues', []))))
        if item.get('Scope'):
            lines.append('      Scope: {}'.format(item['Scope']))
    lines.append('  ' + permissions['Limitations'])
    lines.append('  No mutation APIs executed. Full results: data CloudTrail -> SecurityPosture.')
    return '\n'.join(lines)
