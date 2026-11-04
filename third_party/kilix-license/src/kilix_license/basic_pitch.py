"""Separately pinned unchanged upstream Basic Pitch ONNX model terms.

This authority covers model bytes and verbatim upstream notices. It does not
license or select a Python/runtime wheel closure, audio dataset or local export.
"""
from .digest import sha256_hex, load_json_object
from .generate import load_pin, load_text_file
from .records import LicenseRecord

MODEL_ID = 'basic-pitch-icassp-2022-onnx'
LICENSE_SHA256 = '929c910bae2152fa87199a5d0660e09263419b7eee6d4b301d05ee2aaf211c37'
NOTICE_SHA256 = 'b810e55c0e3b520fabb45fc2ccc74880187bf84e309971968541cc812dcde905'
MODEL_SHA256 = '2c3c1d144bfa61ad236e92e169c13535c880469a12a047d4e73451f2c059a0ec'
REVISION = '9991303bba609a3b93089d13ec80d1d495083596'


def generate_basic_pitch_records(directory):
    raw = (directory / 'determinations-basic-pitch.json').read_bytes()
    pin = load_pin(directory, 'determinations-basic-pitch.sha256')
    if sha256_hex(raw) != pin:
        raise ValueError('Basic Pitch determination pin mismatch')
    data = load_json_object(raw, label='Basic Pitch determination')
    if data.get('schema') != 'kilix.license.basic-pitch-determination/v1' or len(data.get('records', [])) != 1:
        raise ValueError('unsupported Basic Pitch determination')
    authority = data['authority']
    if (authority['model_sha256'], authority['model_bytes'], authority['revision']) != (MODEL_SHA256, 230444, REVISION):
        raise ValueError('unexpected Basic Pitch upstream model binding')
    if authority['licence_sha256'] != LICENSE_SHA256 or authority['notice_sha256'] != NOTICE_SHA256:
        raise ValueError('unexpected Basic Pitch original documents')
    record = LicenseRecord.from_mapping(dict(data['records'][0], determinations_sha256=pin))
    if record.id != MODEL_ID or record.licence_text_id != 'github.com/spotify/basic-pitch/LICENSE':
        raise ValueError('unexpected Basic Pitch licence identity')
    if record.licensor != 'Spotify AB' or record.licence_ids != ('Apache-2.0',) or record.decision_class != 'affirmative':
        raise ValueError('unexpected Basic Pitch licence classification')
    if record.text_sha256 != LICENSE_SHA256 or record.binding_conditions or record.components or record.advisories:
        raise ValueError('unexpected Basic Pitch terms or scope')
    if [(s.id, s.text_sha256) for s in record.statements] != [('upstream-notice', NOTICE_SHA256)]:
        raise ValueError('Basic Pitch must preserve the original full NOTICE')
    for digest in (LICENSE_SHA256, NOTICE_SHA256):
        load_text_file(directory / 'texts', digest, record.id)
    return [record]
