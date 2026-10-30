#!/usr/bin/env python3
"""校验客户端契约及正反样本；依赖 jsonschema>=4，不联网解析引用。"""
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker, ValidationError, validators

ROOT = Path(__file__).resolve().parents[1]
schema = json.loads((ROOT / 'api/control-session.schema.json').read_text())

def decimal_limit(validator, maximum, value, subschema):
    if isinstance(value, str) and value.isascii() and value.isdecimal() and int(value) > int(maximum):
        yield ValidationError('十进制字符串溢出')

Validator = validators.extend(Draft202012Validator, {'x-maximum-decimal': decimal_limit})
Validator.check_schema(schema)

def check_refs(node):
    if isinstance(node, dict):
        if '$ref' in node:
            assert node['$ref'].startswith('#/'), '禁止网络引用'
            target = schema
            for part in node['$ref'][2:].split('/'):
                target = target[part.replace('~1', '/').replace('~0', '~')]
        for value in node.values():
            check_refs(value)
    elif isinstance(node, list):
        for value in node:
            check_refs(value)

check_refs(schema)
fixtures = json.loads((ROOT / 'api/fixtures/control-session.json').read_text())
cases = fixtures['cases']
for case in cases:
    target = schema if 'definition' not in case else {'$ref': '#/$defs/' + case['definition'], '$defs': schema['$defs']}
    valid = Validator(target, format_checker=FormatChecker()).is_valid(case['message'])
    assert valid == case['valid'], case['name']
for case in fixtures['attach_cases']:
    valid = case['video'] == 'qm.v1.video.' + case['generation'] and case['control'] == 'qm.v1.control.' + case['generation']
    assert valid == case['valid'], case['name']
video = fixtures['video_fixture']
wire = bytes.fromhex(video['wire_hex'])
assert wire[0] == 0 and len(wire[1:65]) == 64
assert wire[1:65].split(b'\0')[0].decode('utf-8') == video['device_name']
assert int.from_bytes(wire[65:69], 'big') == 0x68323634
assert int.from_bytes(wire[69:73], 'big') == video['width']
assert int.from_bytes(wire[73:77], 'big') == video['height']
assert int.from_bytes(wire[77:85], 'big') == video['pts_us']
assert int.from_bytes(wire[85:89], 'big') == len(wire[89:])
assert wire[89:].hex() == video['payload_hex']
print(f'通过：schema/local refs/{len(cases)} 正反结构样本/3 label绑定样本/65+12字节媒体布局。未运行 SDK 或真机链路。')

expected_timelines = {'partial_stream_open', 'start_timeout_unknown', 'late_permission_after_cancel', 'backpressure_cancel', 'old_media_new_core', 'active_script_survives', 'quit_before_event_loop_exit'}
timelines = fixtures['timeline_contract']['cases']
assert {case['id'] for case in timelines} == expected_timelines
assert len(timelines) == len(expected_timelines)
assert all(case['steps'] and case['expect'] and all(isinstance(v, str) for v in case['steps'] + case['expect']) for case in timelines)
print('7个时序契约仅检查结构/存在性；未执行状态机、资源排空或真机行为。')
