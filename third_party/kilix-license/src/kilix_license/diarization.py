"""Independently pinned, digest-specific F104 diarization determination.

Adding this approved route leaves the earlier release/application records and
their receipt bindings unchanged.
"""
from .digest import sha256_hex, load_json_object
from .generate import load_pin, load_text_file
from .records import LicenseRecord

RECORDS_DIRNAME = 'diarization-records'
LICENCE_TEXT_IDS = {'kilix-diarization-cpu':'debian/common-licenses/Apache-2.0'}

def generate_diarization_records(directory):
    data = (directory/'determinations-diarization.json').read_bytes()
    pin = load_pin(directory,'determinations-diarization.sha256')
    if sha256_hex(data) != pin:
        raise ValueError('diarization determination pin mismatch')
    value = load_json_object(data,label='diarization determination')
    if (value.get('schema') != 'kilix.license.diarization-determination/v1'
            or len(value.get('records',[])) != 1):
        raise ValueError('unsupported diarization determination')
    records = []
    for raw in value['records']:
        record = LicenseRecord.from_mapping(dict(raw,determinations_sha256=pin))
        if record.id != 'kilix-diarization-cpu':
            raise ValueError('unexpected diarization record')
        if record.licence_text_id != LICENCE_TEXT_IDS[record.id]:
            raise ValueError('diarization licence text identity mismatch')
        digests = [record.text_sha256]
        digests += [x.exception_text_sha256 for x in record.components if x.exception_text_sha256]
        digests += [x.text_sha256 for x in record.statements]
        digests.append(value['authority']['native_software_notice_sha256'])
        for digest in digests:
            load_text_file(directory/'texts',digest,record.id)
        if (value['authority']['weight_determination_sha256']
                != next(x.text_sha256 for x in record.statements if x.id == 'campp-digest-specific-grant')):
            raise ValueError('diarization weight grant is not displayed')
        records.append(record)
    return records
