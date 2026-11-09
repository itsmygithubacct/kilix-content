"""Separately pinned terms for qwen-0.8b-no-loop-02.

The GGUF is Qwen3.5-0.8B (Apache-2.0, Alibaba Cloud), modified by
itsmygithubacct with a weight edit adapted from CC BY 4.0 material. Earlier
receipt bindings are unchanged, and this file does not fetch the weights.

The owner approved both components on 2026-11-09: Apache-2.0 as proposed,
and the CC BY 4.0 weight-edit component covered by the standard distribution
policy, like kilix-female-02 (no separate typed answer). The determination's
owner_determination block records both decisions.
"""
from .digest import sha256_hex, load_json_object
from .generate import load_pin, load_text_file
from .records import LicenseRecord

APACHE = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
CC_BY = "9ba9550ad48438d0836ddab3da480b3b69ffa0aac7b7878b5a0039e7ab429411"
SOURCE_LICENCE = "395f7febedfda6b5498ca36cfe3344d3986659ce4385dd8b03d2d75604250a8e"
LICENCE_TEXT_IDS = {"qwen-0.8b-no-loop-02": "debian/common-licenses/Apache-2.0"}
EDIT_LICENSOR = 'the authors of "LLMs can understand and write neural network weights"'
# itsmygithubacct is the modifier (authority "modifier"), not a licensor.
LICENSOR = "Alibaba Cloud / Qwen; " + EDIT_LICENSOR
COMPONENT = "weight-edit-from-lm-understand-logs"
SOURCE = ("https://github.com/itsmygithubacct/kilix-llm/releases/download/"
          "qwen-0.8b-no-loop-02/qwen-0.8b-no-loop-02.gguf")
MODEL_SHA256 = "e4d6e93eb644da62e0c5ac0b7b188b4c2cbf31f07a7dcfd42764b6236f96d8a0"


def generate_noloop02_records(directory):
    data = (directory / "determinations-noloop02.json").read_bytes()
    pin = load_pin(directory, "determinations-noloop02.sha256")
    if sha256_hex(data) != pin:
        raise ValueError("no-loop-02 determination pin mismatch")
    value = load_json_object(data, label="no-loop-02 determination")
    if value.get("schema") != "kilix.license.noloop02-determination/v1" or len(value.get("records", [])) != 1:
        raise ValueError("unsupported no-loop-02 determination")
    authority = value.get("authority") or {}
    if (authority.get("model") != "qwen-0.8b-no-loop-02" or authority.get("source") != SOURCE
            or authority.get("model_sha256") != MODEL_SHA256):
        raise ValueError("unexpected no-loop-02 authority")
    record = LicenseRecord.from_mapping(dict(value["records"][0], determinations_sha256=pin))
    if record.id not in LICENCE_TEXT_IDS or record.licence_text_id != LICENCE_TEXT_IDS[record.id]:
        raise ValueError("unexpected no-loop-02 licence identity")
    if record.licence_ids != ("Apache-2.0", "CC-BY-4.0") or record.decision_class != "affirmative":
        raise ValueError("no-loop-02 must be an affirmative Apache-2.0 and CC BY 4.0 record")
    if record.licensor != LICENSOR or authority.get("edit_licensor") != EDIT_LICENSOR:
        raise ValueError("unexpected no-loop-02 licensor")
    if record.text_sha256 != authority.get("licence_sha256") or record.text_sha256 != APACHE:
        raise ValueError("no-loop-02 licence is not displayed")
    if ([(x.id, x.exception_text_sha256) for x in record.components] != [(COMPONENT, CC_BY)]
            or authority.get("edit_licence_sha256") != CC_BY):
        raise ValueError("no-loop-02 CC BY 4.0 component is not displayed")
    statements = {x.id: x.text_sha256 for x in record.statements}
    if "modified-model" not in statements or "weight-edit-attribution" not in statements:
        raise ValueError("no-loop-02 modification and attribution notices are not displayed")
    if (statements.get("weight-edit-source-licence") != SOURCE_LICENCE
            or authority.get("edit_source_licence_file_sha256") != SOURCE_LICENCE):
        raise ValueError("no-loop-02 edit source licence file is not displayed")
    if record.binding_conditions or record.advisories:
        raise ValueError("unexpected no-loop-02 terms")
    digests = [record.text_sha256, CC_BY]
    digests += [x.text_sha256 for x in record.statements]
    for digest in digests:
        load_text_file(directory / "texts", digest, record.id)
    return [record]
