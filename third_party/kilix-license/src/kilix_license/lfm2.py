"""Independently pinned LFM2 terms; earlier receipt bindings are unchanged."""
from .digest import sha256_hex, load_json_object
from .generate import load_pin, load_text_file
from .records import LicenseRecord


LICENCE_TEXT_IDS = {'lfm2-kilix-commands': 'liquid-ai/lfm-open-license-v1'}

def generate_lfm2_records(directory):
    data = (directory / 'determinations-lfm2.json').read_bytes()
    pin = load_pin(directory, 'determinations-lfm2.sha256')
    if sha256_hex(data) != pin:
        raise ValueError('LFM2 determination pin mismatch')
    value = load_json_object(data, label='LFM2 determination')
    if value.get('schema') != 'kilix.license.lfm2-determination/v1' or len(value.get('records', [])) != 1:
        raise ValueError('unsupported LFM2 determination')
    record = LicenseRecord.from_mapping(dict(value['records'][0], determinations_sha256=pin))
    if record.id != 'lfm2-kilix-commands' or record.licence_text_id != 'liquid-ai/lfm-open-license-v1':
        raise ValueError('unexpected LFM2 licence identity')
    if record.text_sha256 != value['authority']['licence_sha256']:
        raise ValueError('LFM2 licence is not displayed')
    if value['authority']['runtime_notice_sha256'] not in [x.exception_text_sha256 for x in record.components]:
        raise ValueError('LFM2 runtime notice is not displayed')
    digests = [record.text_sha256]
    digests += [x.exception_text_sha256 for x in record.components if x.exception_text_sha256]
    digests += [x.text_sha256 for x in record.binding_conditions + record.statements]
    for digest in digests:
        load_text_file(directory / 'texts', digest, record.id)
    return [record]
