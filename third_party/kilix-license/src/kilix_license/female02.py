"""Separately pinned terms for Kilix Female-02 epoch 80.

Earlier receipt bindings are unchanged. The weights are published by
itsmygithubacct under Apache-2.0; this file does not rewrite those terms.
"""
from .digest import sha256_hex, load_json_object
from .generate import load_pin, load_text_file
from .records import LicenseRecord

APACHE = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
LICENCE_TEXT_IDS = {"kilix-female-02": "debian/common-licenses/Apache-2.0"}


def generate_female02_records(directory):
    data = (directory / "determinations-female02.json").read_bytes()
    pin = load_pin(directory, "determinations-female02.sha256")
    if sha256_hex(data) != pin:
        raise ValueError("Female-02 determination pin mismatch")
    value = load_json_object(data, label="Female-02 determination")
    if value.get("schema") != "kilix.license.female02-determination/v1" or len(value.get("records", [])) != 1:
        raise ValueError("unsupported Female-02 determination")
    record = LicenseRecord.from_mapping(dict(value["records"][0], determinations_sha256=pin))
    if record.id not in LICENCE_TEXT_IDS or record.licence_text_id != LICENCE_TEXT_IDS[record.id]:
        raise ValueError("unexpected Female-02 licence identity")
    if record.licence_ids != ("Apache-2.0",) or record.decision_class != "affirmative":
        raise ValueError("Female-02 must be an affirmative Apache-2.0 record")
    if record.licensor != "itsmygithubacct":
        raise ValueError("unexpected Female-02 licensor")
    if record.text_sha256 != value["authority"]["licence_sha256"] or record.text_sha256 != APACHE:
        raise ValueError("Female-02 licence is not displayed")
    load_text_file(directory / "texts", record.text_sha256, record.id)
    return [record]
