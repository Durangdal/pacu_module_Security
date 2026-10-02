"""Read-only CloudTrail posture enumeration for Pacu (no IAM probes)."""
import argparse
import json
from copy import deepcopy
from datetime import datetime, timezone
from fnmatch import fnmatchcase

from botocore.exceptions import BotoCoreError, ClientError

module_info = {
    'name': 'cloudtrail__enum_security',
    'author': 'Pacu community',
    'category': 'ENUM',
    'one_liner': 'Read-only CloudTrail security and detection linkage inventory.',
    'description': 'Reads CloudTrail, storage and detection configuration. '
                   'Uses only cached active-key IAM evidence; never tests mutation APIs. '
                   'Denied or unavailable sections remain UNKNOWN. API reads may be logged.',
    'services': ['CloudTrail', 'S3', 'KMS', 'logs', 'monitoring', 'SNS', 'EventBridge'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': ['--regions', '--use-cached-trails'],
}
parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--regions', help='Comma-separated discovery/EventBridge regions; default: session regions.')
parser.add_argument('--use-cached-trails', action='store_true',
                    help='Reuse session.CloudTrail.Trails, potentially stale; still refresh details.')

DANGEROUS = {
    'CRITICAL': ['cloudtrail:StopLogging', 'cloudtrail:DeleteTrail'],
    'HIGH': ['cloudtrail:UpdateTrail', 'cloudtrail:PutEventSelectors', 'cloudtrail:PutInsightSelectors'],
    'STORAGE': ['s3:DeleteObject', 's3:DeleteObjectVersion'],
    'DETECTION': ['logs:DeleteMetricFilter', 'cloudwatch:DeleteAlarms', 'events:DisableRule'],
}
# Defense in depth: every dispatched operation must appear in this read-only list.
READS = {
    'cloudtrail': {'describe_trails', 'get_trail_status', 'get_event_selectors', 'get_insight_selectors'},
    's3': {'get_bucket_location', 'get_bucket_policy', 'get_bucket_versioning',
           'get_object_lock_configuration', 'get_bucket_encryption'},
    'kms': {'describe_key', 'get_key_policy', 'get_key_rotation_status'},
    'logs': {'describe_log_groups', 'describe_metric_filters'},
    'cloudwatch': {'describe_alarms'},
    'events': {'list_event_buses', 'list_rules', 'list_targets_by_rule'},
    'sns': {'get_topic_attributes', 'list_subscriptions_by_topic'},
}


def clean(value):
    """Pacu JSON columns require serializable values (AWS returns datetimes)."""
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items() if k != 'ResponseMetadata'}
    if isinstance(value, (list, tuple)):
        return [clean(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


class Reader:
    def __init__(self, pacu):
        self.pacu = pacu
        self.cache = {}

    def read(self, service, region, operation, keys=None, token=None, **kwargs):
        if operation not in READS.get(service, set()):
            raise AssertionError('Only explicitly approved read APIs are allowed')
        cache_key = (service, region, operation, json.dumps(kwargs, sort_keys=True))
        if cache_key in self.cache:
            return deepcopy(self.cache[cache_key])
        collected = {key: [] for key in keys or []}
        result = {'Status': 'UNKNOWN', 'Data': collected}
        try:
            client = self.pacu.get_boto3_client(service, region)
            if client is None:
                raise ValueError('Pacu could not create a client')
            seen = set()
            while True:
                response = clean(getattr(client, operation)(**kwargs))
                if keys is None:
                    result = {'Status': 'OK', 'Data': response}
                    break
                for key in keys:
                    collected[key].extend(response.get(key, []))
                next_token = response.get(token) if token else None
                if not next_token:
                    result = {'Status': 'OK', 'Data': collected}
                    break
                if next_token in seen:
                    raise ValueError('Repeated pagination token')
                seen.add(next_token)
                kwargs[token] = next_token
        except ClientError as error:
            code = error.response.get('Error', {}).get('Code', 'Unknown')
            status = 'ACCESS DENIED' if ('accessdenied' in code.lower() or
                                        code in ('UnauthorizedOperation', 'AuthorizationError')) else 'UNKNOWN'
            result.update(Status=status, ErrorCode=code)
            if code in ('NoSuchBucketPolicy', 'ObjectLockConfigurationNotFoundError',
                        'ServerSideEncryptionConfigurationNotFoundError'):
                result.update(Status='NOT CONFIGURED', Data={})
        except (BotoCoreError, ValueError, AttributeError) as error:
            result.update(ErrorCode=type(error).__name__)
        self.cache[cache_key] = deepcopy(result)
        if result['Status'] in ('UNKNOWN', 'ACCESS DENIED'):
            self.pacu.print('  {}: {} / {} / {}'.format(result['Status'], service, region, operation))
        return result


def arn_region(arn, fallback):
    parts = (arn or '').split(':')
    return parts[3] if len(parts) > 5 and parts[3] else fallback


def permissions(pacu):
    """Flattened cached policies are evidence, never effective authorization."""
    key = pacu.key_info() or {}
    cached = key.get('Permissions') or {}
    output = []
    for severity, actions in DANGEROUS.items():
        for action in actions:
            evidence = {}
            for effect in ('Allow', 'Deny'):
                entries = cached.get(effect) or {}
                evidence[effect] = {pattern: clean(detail) for pattern, detail in entries.items()
                                    if fnmatchcase(action.lower(), pattern.lower())}
            output.append({'Action': action, 'Severity': severity, 'EffectivePermission': 'UNKNOWN',
                           'PolicyEvidence': ('ALLOW_AND_DENY' if all(evidence.values()) else
                                              'ALLOW' if evidence['Allow'] else
                                              'DENY' if evidence['Deny'] else 'UNKNOWN'),
                           'Evidence': evidence,
                           'PermissionsConfirmed': key.get('PermissionsConfirmed', False)})
    return output


def kms(reader, key_id, fallback):
    region = arn_region(key_id, fallback)
    return {'KeyId': key_id,
            'Metadata': reader.read('kms', region, 'describe_key', KeyId=key_id),
            'Policy': reader.read('kms', region, 'get_key_policy', KeyId=key_id, PolicyName='default'),
            'Rotation': reader.read('kms', region, 'get_key_rotation_status', KeyId=key_id)}


def storage(reader, trail, home):
    bucket = trail.get('S3BucketName')
    if not bucket:
        return {'Status': 'UNKNOWN', 'Reason': 'Trail did not provide S3BucketName'}
    location = reader.read('s3', home, 'get_bucket_location', Bucket=bucket)
    loc = location.get('Data', {}).get('LocationConstraint')
    region = ('us-east-1' if loc is None else 'eu-west-1' if loc == 'EU' else loc) if location['Status'] == 'OK' else home
    output = {'Bucket': bucket, 'Region': region, 'Location': location,
              'LogPrefix': trail.get('S3KeyPrefix', ''),
              'DigestVerification': 'UNKNOWN: digest objects/signatures were not downloaded or verified'}
    for label, operation in [('Policy', 'get_bucket_policy'), ('Versioning', 'get_bucket_versioning'),
                             ('ObjectLock', 'get_object_lock_configuration'), ('Encryption', 'get_bucket_encryption')]:
        output[label] = reader.read('s3', region, operation, Bucket=bucket)
    output['KMS'] = []
    for rule in output['Encryption'].get('Data', {}).get('ServerSideEncryptionConfiguration', {}).get('Rules', []):
        key = rule.get('ApplyServerSideEncryptionByDefault', {}).get('KMSMasterKeyID')
        if key:
            output['KMS'].append(kms(reader, key, region))
    return output


def logs_pipeline(reader, trail, home):
    arn = trail.get('CloudWatchLogsLogGroupArn')
    if not arn:
        return {'Status': 'NOT CONFIGURED', 'MetricFilters': {'Status': 'NOT CONFIGURED', 'Data': {}}}
    region = arn_region(arn, home)
    group = arn.split(':log-group:', 1)[-1].removesuffix(':*')
    groups = reader.read('logs', region, 'describe_log_groups', keys=['logGroups'], token='nextToken',
                         logGroupNamePrefix=group)
    groups['Data']['logGroups'] = [g for g in groups['Data'].get('logGroups', []) if g.get('logGroupName') == group]
    filters = reader.read('logs', region, 'describe_metric_filters', keys=['metricFilters'],
                          token='nextToken', logGroupName=group)
    alarms = reader.read('cloudwatch', region, 'describe_alarms', keys=['MetricAlarms', 'CompositeAlarms'],
                         token='NextToken', AlarmTypes=['MetricAlarm', 'CompositeAlarm'])
    metrics = {(m.get('metricNamespace'), m.get('metricName'))
               for f in filters['Data'].get('metricFilters', []) for m in f.get('metricTransformations', [])}
    linked = []
    for alarm in alarms['Data'].get('MetricAlarms', []):
        references = {(alarm.get('Namespace'), alarm.get('MetricName'))}
        references.update((m.get('MetricStat', {}).get('Metric', {}).get('Namespace'),
                           m.get('MetricStat', {}).get('Metric', {}).get('MetricName'))
                          for m in alarm.get('Metrics', []))
        if references & metrics:
            linked.append(alarm)
    return {'Status': groups['Status'], 'LogGroupArn': arn, 'LogGroup': groups, 'MetricFilters': filters,
            'RegionalAlarmInventory': alarms, 'CandidateMetricAlarms': linked,
            'Correlation': 'Namespace/name candidates only; dimensions and expressions require review. '
                           'Composite alarms are inventoried, not recursively resolved.'}


def eventbridge(reader, region):
    buses = reader.read('events', region, 'list_event_buses', keys=['EventBuses'], token='NextToken')
    output = {'EventBuses': buses, 'Buses': []}
    for bus in buses['Data'].get('EventBuses', []):
        name = bus['Name']
        rules = reader.read('events', region, 'list_rules', keys=['Rules'], token='NextToken', EventBusName=name)
        entries = []
        for rule in rules['Data'].get('Rules', []):
            # Inventory all patterns: string matching cannot prove CloudTrail coverage.
            entries.append({'Rule': rule, 'Targets': reader.read(
                'events', region, 'list_targets_by_rule', keys=['Targets'], token='NextToken',
                EventBusName=name, Rule=rule['Name'])})
        output['Buses'].append({'Name': name, 'Rules': rules, 'Entries': entries})
    output['Correlation'] = 'Inventory only; event pattern applicability and downstream forwarding are UNKNOWN.'
    return output


def main(args, pacu_main):
    args = parser.parse_args(args)
    session = pacu_main.get_active_session()
    reader = Reader(pacu_main)
    regions = list(dict.fromkeys(r.strip() for r in args.regions.split(',') if r.strip())) if args.regions else list(pacu_main.get_regions('cloudtrail') or [])
    result = {'CollectedAt': datetime.now(timezone.utc).isoformat(), 'Regions': regions,
              'Discovery': {}, 'Trails': [], 'EventBridge': {}, 'SNS': {},
              'DangerousPermissions': permissions(pacu_main),
              'Scope': 'Trails only; CloudTrail Lake, external SIEM and forwarded events are not assessed.'}
    trails = []
    if args.use_cached_trails:
        trails = deepcopy((session.CloudTrail or {}).get('Trails', []))
        result['Discovery']['Cache'] = {'Status': 'CACHED', 'Reason': 'May be stale or incomplete'}
    else:
        for region in regions:
            pacu_main.print('Enumerating CloudTrail in {}...'.format(region))
            discovery = reader.read('cloudtrail', region, 'describe_trails', includeShadowTrails=True)
            result['Discovery'][region] = discovery
            trails.extend(dict(t, Region=region) for t in discovery['Data'].get('trailList', []))
    seen = set()
    topics = set()
    for trail in trails:
        home = trail.get('HomeRegion') or trail.get('Region')
        identity = trail.get('TrailARN') or (home, trail.get('Name'))
        if identity in seen:
            continue
        seen.add(identity)
        name = trail.get('TrailARN') or trail.get('Name')
        if not home or not name:
            result['Trails'].append({'Configuration': trail, 'Status': 'UNKNOWN', 'Reason': 'Missing trail name/home region'})
            continue
        pacu_main.print('  Reading {} ({})...'.format(trail.get('Name', name), home))
        item = {'Configuration': clean(trail),
                'Logging': reader.read('cloudtrail', home, 'get_trail_status', Name=name),
                'EventCoverage': reader.read('cloudtrail', home, 'get_event_selectors', TrailName=name),
                'Insights': reader.read('cloudtrail', home, 'get_insight_selectors', TrailName=name),
                'Integrity': {'LogFileValidationEnabled': trail.get('LogFileValidationEnabled', 'UNKNOWN'),
                              'DigestVerification': 'UNKNOWN: configuration is not cryptographic verification'},
                'Storage': storage(reader, trail, home),
                'Detection': logs_pipeline(reader, trail, home)}
        if trail.get('KmsKeyId'):
            item['KMS'] = kms(reader, trail['KmsKeyId'], home)
        if trail.get('SnsTopicARN'):
            topics.add(trail['SnsTopicARN'])
        for alarm in item['Detection'].get('CandidateMetricAlarms', []):
            for field in ('AlarmActions', 'OKActions', 'InsufficientDataActions'):
                topics.update(a for a in alarm.get(field, []) if a.startswith('arn:') and ':sns:' in a)
        result['Trails'].append(item)
    # Logs may reside outside the selected discovery regions. EventBridge scan is explicitly scoped.
    for region in regions:
        pacu_main.print('Enumerating EventBridge in {}...'.format(region))
        result['EventBridge'][region] = eventbridge(reader, region)
        for bus in result['EventBridge'][region]['Buses']:
            for entry in bus['Entries']:
                topics.update(t['Arn'] for t in entry['Targets']['Data'].get('Targets', [])
                              if ':sns:' in t.get('Arn', ''))
    for topic in sorted(topics):
        region = arn_region(topic, regions[0] if regions else None)
        result['SNS'][topic] = {'Attributes': reader.read('sns', region, 'get_topic_attributes', TopicArn=topic),
                               'Subscriptions': reader.read('sns', region, 'list_subscriptions_by_topic',
                                                            keys=['Subscriptions'], token='NextToken', TopicArn=topic)}
    cloudtrail_data = deepcopy(session.CloudTrail or {})
    cloudtrail_data['SecurityPosture'] = clean(result)
    session.update(pacu_main.database, CloudTrail=cloudtrail_data)
    return result


def summary(data, pacu_main):
    lines = ['Security Summary', '  Scope: {}'.format(data['Scope']),
             '  Trails observed: {} (not proof of complete account coverage)'.format(len(data['Trails']))]
    for item in data['Trails']:
        cfg = item['Configuration']
        logging = item.get('Logging', {})
        state = logging.get('Data', {}).get('IsLogging', 'UNKNOWN') if logging.get('Status') == 'OK' else logging.get('Status', 'UNKNOWN')
        lines.append('  {} | Home={} | MultiRegion={} | Organization={} | Logging={} | Validation={}'.format(
            cfg.get('Name', 'UNKNOWN'), cfg.get('HomeRegion', 'UNKNOWN'), cfg.get('IsMultiRegionTrail', 'UNKNOWN'),
            cfg.get('IsOrganizationTrail', 'UNKNOWN'), state, cfg.get('LogFileValidationEnabled', 'UNKNOWN')))
        coverage = item.get('EventCoverage', {})
        if coverage.get('Status') == 'OK':
            lines.append('    Event coverage (review exclusions and advanced field logic): {}'.format(json.dumps(coverage['Data'], sort_keys=True)))
        else:
            lines.append('    Event coverage: {}'.format(coverage.get('Status', 'UNKNOWN')))
        if state is False:
            lines.append('    FINDING: trail is not currently logging.')
        if cfg.get('LogFileValidationEnabled') is False:
            lines.append('    FINDING: log file validation is disabled.')
        store = item.get('Storage', {})
        lines.append('    Storage: {}'.format(', '.join('{}={}'.format(k, store.get(k, {}).get('Status', 'UNKNOWN'))
                                                      for k in ('Policy', 'Versioning', 'ObjectLock', 'Encryption'))))
        if store.get('Versioning', {}).get('Status') == 'OK' and store['Versioning']['Data'].get('Status') != 'Enabled':
            lines.append('    REVIEW: bucket versioning is not enabled.')
        detect = item.get('Detection', {})
        lines.append('    CloudWatch Logs={} | Metric filters={} | Candidate alarms={}'.format(
            detect.get('Status', 'UNKNOWN'), detect.get('MetricFilters', {}).get('Status', 'UNKNOWN'),
            len(detect.get('CandidateMetricAlarms', []))))
    lines.append('  Dangerous permissions (cached active-key policy evidence; effective authorization UNKNOWN):')
    for permission in data['DangerousPermissions']:
        lines.append('    [{}] {}: {} / effective UNKNOWN'.format(permission['Severity'], permission['Action'], permission['PolicyEvidence']))
    counts = {}
    def count(value):
        if isinstance(value, dict):
            status = value.get('Status')
            if status in ('ACCESS DENIED', 'UNKNOWN'):
                counts[status] = counts.get(status, 0) + 1
            for child in value.values():
                count(child)
        elif isinstance(value, list):
            for child in value:
                count(child)
    count(data)
    lines.extend(['  Unavailable sections: {}'.format(counts),
                  '  EventBridge regions={} | Linked SNS topics={}'.format(len(data['EventBridge']), len(data['SNS'])),
                  '  Digest authenticity, SCPs, boundaries, session policies and end-to-end alert delivery: UNKNOWN.',
                  '  Full configuration/evidence: data CloudTrail -> SecurityPosture.'])
    return '\n'.join(lines)
