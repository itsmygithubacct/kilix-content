"""Separately pinned terms for OpenAI Whisper medium.en (faster-whisper).

The owner determined Systran/faster-whisper-medium.en at a29b04bd on
2026-11-07: MIT, licensors OpenAI (weights) and SYSTRAN (CTranslate2
conversion), the same terms as faster-whisper-small-en. The record reuses that
licence text, statement and advisory; only the artifact differs. It lives in
its own family so that no release record digest moves. On 2026-11-08 the
owner also decided its distribution: from Plebian-OS 0.2.3 RC5 an online
upgrade downloads it by default for Kilix Playalong unless declined; it is still
never shipped. This file does not fetch the weights.
"""
from .digest import sha256_hex, load_json_object
from .generate import load_pin, load_text_file
from .records import LicenseRecord

MODEL_ID = "faster-whisper-medium-en"
REPOSITORY = "https://huggingface.co/Systran/faster-whisper-medium.en"
REVISION = "a29b04bd15381511a9af671baec01072039215e3"
FILES = (
    ("config.json", 2643, "4a1848ebabe7938d9797c15a2e8e4ce1d36e6fd4a43d096ae5955257c67c7962"),
    ("model.bin", 1527904330, "11b220779aea4c6f3ce9d2549c8a95ea869ed84066864b999531ef53e594fe5b"),
    ("tokenizer.json", 2128466, "929c5252409436dce1b38a75d1abbcb5e132d170d8e324e4e04ed915fa2d22df"),
    ("vocabulary.txt", 422309, "ff77588746d3a2595d32ab5b69ffd7b95ce2441ac57533cb66fc3eb575a115cf"),
)
CARD_SHA256 = "ab3ddd3b6af4ea0ef353cb80004f26613ba33217f81652fc13738d3b098c7675"
# The Whisper MIT text, copyright statement and model-card caution, exactly as
# faster-whisper-small-en carries them.
LICENCE_SHA256 = "b5d65a59060e68c4ff940e1eddfa6f94b2d68fdf58ed7f4dd57721c997e35e9d"
STATEMENTS = (("whisper-notice-copyright", "94536c807e7ad8257102a5db0496db0bf1753fc8b32cba9188e337d9796db7d0"),)
ADVISORIES = (("whisper-card-caution", "0e9d0d19fa02b8f246d9902d93a2b0b0fac7cb07a518257ffa7d102d1c37c638"),)
# The owner's 2026-11-08 distribution decision: an online upgrade downloads it
# by default for Kilix Playalong unless declined. Still never shipped; the
# terms above are unchanged by it.
DISTRIBUTION_RECORD = (
    "licence-evidence-whisper-medium-en-2026-11-07/OWNER-DISTRIBUTION-whisper-medium-en-2026-11-08.md",
    2515, "6798bb899670fc0c1ce3b11bf07fcd0afe6ca9447f15ecde3714a74600850a65")


def generate_whisper_medium_records(directory):
    raw = (directory / "determinations-whisper-medium.json").read_bytes()
    pin = load_pin(directory, "determinations-whisper-medium.sha256")
    if sha256_hex(raw) != pin:
        raise ValueError("Whisper medium determination pin mismatch")
    data = load_json_object(raw, label="Whisper medium determination")
    if (data.get("schema") != "kilix.license.whisper-medium-determination/v1"
            or len(data.get("records", [])) != 1):
        raise ValueError("unsupported Whisper medium determination")
    authority = data.get("authority") or {}
    files = tuple((f.get("path"), f.get("bytes"), f.get("sha256")) for f in authority.get("files", []))
    if (authority.get("repository"), authority.get("revision"), files) != (REPOSITORY, REVISION, FILES):
        raise ValueError("unexpected Whisper medium upstream binding")
    if authority.get("card_sha256") != CARD_SHA256 or authority.get("card_licence_line") != "license: mit":
        raise ValueError("unexpected Whisper medium model card")
    if tuple(((authority.get("distribution") or {}).get("owner_record") or {}).get(k)
             for k in ("path", "bytes", "sha256")) != DISTRIBUTION_RECORD:
        raise ValueError("Whisper medium distribution lacks the owner's decision")
    if authority.get("licence_sha256") != LICENCE_SHA256:
        raise ValueError("Whisper medium licence is not displayed")
    record = LicenseRecord.from_mapping(dict(data["records"][0], determinations_sha256=pin))
    if record.id != MODEL_ID or record.licence_text_id != "kilix/config/model_notices#whisper":
        raise ValueError("unexpected Whisper medium licence identity")
    if (record.licensor != "OpenAI; SYSTRAN" or record.licence_ids != ("MIT",)
            or record.decision_class != "affirmative"):
        raise ValueError("unexpected Whisper medium licence classification")
    if record.text_sha256 != LICENCE_SHA256 or record.binding_conditions or record.components:
        raise ValueError("unexpected Whisper medium terms or scope")
    if tuple((s.id, s.text_sha256) for s in record.statements) != STATEMENTS:
        raise ValueError("Whisper medium must carry the Whisper copyright statement")
    if tuple((a.id, a.text_sha256) for a in record.advisories) != ADVISORIES:
        raise ValueError("Whisper medium must carry the Whisper model card caution")
    for digest in (LICENCE_SHA256, *(d for _, d in STATEMENTS), *(d for _, d in ADVISORIES)):
        load_text_file(directory / "texts", digest, record.id)
    return [record]
