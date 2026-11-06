"""Separately pinned terms for Paradee 1.2.

The weights are published by Sahil Mahendrakar under Apache-2.0. This file
does not rewrite those terms and does not fetch the weights.
"""
from .digest import sha256_hex, load_json_object
from .generate import load_pin, load_text_file
from .records import LicenseRecord

APACHE = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
LICENCE_TEXT_IDS = {"paradee-8m-v1.2": "debian/common-licenses/Apache-2.0"}
SOURCE = ("https://huggingface.co/sahilmahendrakar/Paradee-8M-v1.2/resolve/"
          "ed2934d4df8a4fd891e29584c5e1104649409765/onnx/paradee_int8.onnx")


def generate_paradee_records(directory):
    data = (directory / "determinations-paradee.json").read_bytes()
    pin = load_pin(directory, "determinations-paradee.sha256")
    if sha256_hex(data) != pin:
        raise ValueError("Paradee determination pin mismatch")
    value = load_json_object(data, label="Paradee determination")
    if value.get("schema") != "kilix.license.paradee-determination/v1" or len(value.get("records", [])) != 1:
        raise ValueError("unsupported Paradee determination")
    authority = value.get("authority") or {}
    if authority.get("model") != "paradee-8m-v1.2" or authority.get("source") != SOURCE:
        raise ValueError("unexpected Paradee authority")
    if authority.get("licence_sha256") != APACHE:
        raise ValueError("Paradee licence is not displayed")
    record = LicenseRecord.from_mapping(dict(value["records"][0], determinations_sha256=pin))
    if record.id not in LICENCE_TEXT_IDS or record.licence_text_id != LICENCE_TEXT_IDS[record.id]:
        raise ValueError("unexpected Paradee licence identity")
    if record.licence_ids != ("Apache-2.0",) or record.decision_class != "affirmative":
        raise ValueError("Paradee must be an affirmative Apache-2.0 record")
    if record.licensor != "Sahil Mahendrakar":
        raise ValueError("unexpected Paradee licensor")
    if record.text_sha256 != APACHE:
        raise ValueError("Paradee licence is not displayed")
    load_text_file(directory / "texts", record.text_sha256, record.id)
    return [record]
