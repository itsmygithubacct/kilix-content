"""Separately pinned terms for the optional Needle 3 command model."""
from .digest import sha256_hex, load_json_object
from .generate import load_pin, load_text_file
from .records import LicenseRecord

LICENCE_TEXT_IDS = {'needle3-kilix-commands': 'debian/common-licenses/Apache-2.0'}


def generate_needle3_records(directory):
    data = (directory / 'determinations-needle3.json').read_bytes()
    pin = load_pin(directory, 'determinations-needle3.sha256')
    if sha256_hex(data) != pin:
        raise ValueError('Needle3 determination pin mismatch')
    value = load_json_object(data, label='Needle3 determination')
    if value.get('schema') != 'kilix.license.needle3-determination/v1' or len(value.get('records', [])) != 1:
        raise ValueError('unsupported Needle3 determination')
    record = LicenseRecord.from_mapping(dict(value['records'][0], determinations_sha256=pin))
    if record.id not in LICENCE_TEXT_IDS or record.licence_text_id != LICENCE_TEXT_IDS[record.id]:
        raise ValueError('unexpected Needle3 licence identity')
    if record.text_sha256 != value['authority']['licence_sha256']:
        raise ValueError('Needle3 model licence is not displayed')
    if value['authority']['runtime_notice_sha256'] not in [x.exception_text_sha256 for x in record.components]:
        raise ValueError('Needle3 runtime notice is not displayed')
    digests = [record.text_sha256]
    digests += [x.exception_text_sha256 for x in record.components if x.exception_text_sha256]
    digests += [x.text_sha256 for x in record.binding_conditions + record.statements]
    for digest in digests:
        load_text_file(directory / 'texts', digest, record.id)
    return [record]
