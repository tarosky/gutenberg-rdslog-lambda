import base64
import gzip
import hashlib
import json
import logging
import os
import re
import subprocess
from datetime import datetime

import boto3

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

env = os.environ
commentRe = re.compile(r'\s*([^:]+):\s+((?:\s*[^:\s]|:[^\s])+)(?=\s+\w+: |$)')

int_keys = {
    'Bytes_sent',
    'Rows_affected',
    'Rows_examined',
    'Rows_sent',
    'Thread_id',
}

float_keys = {
    'Lock_time',
    'Query_time',
}

logs = boto3.client('logs')
log_seq_token = None
log_group = env['LOG_GROUP']


class FingerprintError(Exception):
  pass


def decode(data):
  return json.loads(gzip.decompress(base64.b64decode(data)))


def parse(message):
  props = {}
  sqllines = []

  for line in message.split('\n'):
    if line.startswith('# '):
      props.update(dict(commentRe.findall(line[2:])))
      continue

    if line.startswith('SET timestamp='):
      continue

    if line.startswith('use '):
      continue

    sqllines.append(line)

  for k, v in props.items():
    if k in int_keys:
      props[k] = int(v)
    elif k in float_keys:
      props[k] = float(v)

  return '\n'.join(sqllines), props


def fingerprint(sql):
  res = subprocess.run(
      ['pt-fingerprint', '-'], input=sql.encode(), capture_output=True)
  if res.returncode != 0:
    raise FingerprintError(res.stderr.decode())
  return res.stdout.decode()


class LogEvent:

  def __init__(self, timestamp, sql, props, fp, fp_md5):
    self.timestamp = timestamp
    self.sql = sql
    self.props = props
    self.fp = fp
    self.fp_md5 = fp_md5

  @classmethod
  def from_event(cls, log_event):
    sql, props = parse(log_event['message'])
    fp = fingerprint(sql)
    return cls(
        timestamp=datetime.utcfromtimestamp(log_event['timestamp'] / 1000),
        sql=sql,
        props=props,
        fp=fp,
        fp_md5='0x' + hashlib.md5(fp.encode()).hexdigest())

  def json(self):
    return json.dumps(
        {
            '_t': self.timestamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            'sql': self.sql,
            'fp': self.fp,
            'fp_md5': self.fp_md5,
            'props': self.props,
        },
        separators=(',', ':'),
        sort_keys=True)

  def epoch_ms(self):
    return int(self.timestamp.timestamp() * 1000)


def lambda_handler(event, context):
  global log_seq_token

  try:
    data = decode(event['awslogs']['data'])
    log_events = []
    for le in data['logEvents']:
      log_events.append(LogEvent.from_event(le))
  except Exception as ex:
    log.info(event)
    raise ex

  if len(log_events) == 0:
    return

  events = sorted(
      [{
          'timestamp': e.epoch_ms(),
          'message': e.json(),
      } for e in log_events],
      key=lambda ev: ev['timestamp'])

  token_option = {}
  if log_seq_token is None:
    logs.create_log_stream(
        logGroupName=log_group, logStreamName=context.log_stream_name)
  else:
    token_option['sequenceToken'] = log_seq_token

  response = logs.put_log_events(
      logGroupName=log_group,
      logStreamName=context.log_stream_name,
      logEvents=events,
      **token_option)

  log_seq_token = response['nextSequenceToken']
