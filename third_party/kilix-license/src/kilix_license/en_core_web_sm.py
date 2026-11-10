"""Separately pinned terms for spaCy en_core_web_sm 3.8.0.

The wheel is published by ExplosionAI GmbH under the MIT licence shipped in
the wheel. LICENSES_SOURCES is that revision's training-data statement. This
file does not rewrite those terms and does not fetch the wheel.
"""
from .digest import sha256_hex, load_json_object
from .generate import load_pin, load_text_file
from .records import LicenseRecord

MODEL_ID = 'en-core-web-sm-3.8.0'
LICENSE_SHA256 = '3933c176979b68bc6d0bcc902c7d6c130f1d127f476f17ba5cdba8d99cfd0012'
SOURCES_SHA256 = '20d9dfacd215112251f15341edd1a47b1f98bf393a212f10f194ffdc7ee98a90'
WHEEL_SHA256 = '1932429db727d4bff3deed6b34cfc05df17794f4a52eeb26cf8928f7c1a0fb85'
WHEEL_BYTES = 12806118
SOURCE = ('https://github.com/explosion/spacy-models/releases/download/'
          'en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl')
LICENCE_TEXT_IDS = {MODEL_ID: 'github.com/explosion/spacy-models/en_core_web_sm-3.8.0/LICENSE'}


def generate_en_core_web_sm_records(directory):
    raw = (directory / 'determinations-en-core-web-sm.json').read_bytes()
    pin = load_pin(directory, 'determinations-en-core-web-sm.sha256')
    if sha256_hex(raw) != pin:
        raise ValueError('en_core_web_sm determination pin mismatch')
    data = load_json_object(raw, label='en_core_web_sm determination')
    if data.get('schema') != 'kilix.license.en-core-web-sm-determination/v1' or len(data.get('records', [])) != 1:
        raise ValueError('unsupported en_core_web_sm determination')
    authority = data['authority']
    if (authority.get('model'), authority.get('wheel_sha256'), authority.get('wheel_bytes'),
            authority.get('source')) != (MODEL_ID, WHEEL_SHA256, WHEEL_BYTES, SOURCE):
        raise ValueError('unexpected en_core_web_sm wheel binding')
    if authority.get('licence_sha256') != LICENSE_SHA256 or authority.get('sources_sha256') != SOURCES_SHA256:
        raise ValueError('unexpected en_core_web_sm original documents')
    record = LicenseRecord.from_mapping(dict(data['records'][0], determinations_sha256=pin))
    if record.id != MODEL_ID or record.licence_text_id != LICENCE_TEXT_IDS[MODEL_ID]:
        raise ValueError('unexpected en_core_web_sm licence identity')
    if record.licensor != 'ExplosionAI GmbH' or record.licence_ids != ('MIT',) or record.decision_class != 'affirmative':
        raise ValueError('unexpected en_core_web_sm licence classification')
    if record.text_sha256 != LICENSE_SHA256 or record.binding_conditions or record.components or record.advisories:
        raise ValueError('unexpected en_core_web_sm terms or scope')
    if [(item.id, item.text_sha256) for item in record.statements] != [('training-sources', SOURCES_SHA256)]:
        raise ValueError('en_core_web_sm must preserve the upstream training-source statement')
    for digest in (LICENSE_SHA256, SOURCES_SHA256):
        load_text_file(directory / 'texts', digest, record.id)
    return [record]
