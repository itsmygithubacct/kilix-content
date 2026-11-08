"""Separately pinned terms for OpenAI Whisper large-v3 (faster-whisper).

The owner determined Systran/faster-whisper-large-v3 at edaa852e on
2026-11-08: MIT, licensors OpenAI (weights) and SYSTRAN (CTranslate2
conversion), the same terms as faster-whisper-small-en and
faster-whisper-medium-en. The record reuses their licence text, statement and
advisory; only the artifact differs. Kilix Playalong offers it for lyrics that
are not in English, and the user downloads it only after answering yes. It
lives in its own family so that no release record digest moves. This file
does not fetch the weights.
"""
from .digest import sha256_hex, load_json_object
from .generate import load_pin, load_text_file
from .records import LicenseRecord

MODEL_ID = "faster-whisper-large-v3"
REPOSITORY = "https://huggingface.co/Systran/faster-whisper-large-v3"
REVISION = "edaa852ec7e145841d8ffdb056a99866b5f0a478"
FILES = (
    ("config.json", 2394, "a9306624f5ec14270a014b647e5c316b6e03a662c369758d1b90697a7b0655b9"),
    ("model.bin", 3087284237, "69f74147e3334731bc3a76048724833325d2ec74642fb52620eda87352e3d4f1"),
    ("preprocessor_config.json", 340, "7ccc62c6f2765af1f3b46c00c9b5894426835a05021c8b9c01eecb6dfb542711"),
    ("tokenizer.json", 2480617, "6d8cbd7cd0d8d5815e478dac67b85a26bbe77c1f5e0c6d76d1ce2abc0e5f21ca"),
    ("vocabulary.json", 1068114, "c69260f2ab26d659b7c398f9a2b2b48ed0df16c3b47d7326782fd9cba71690c1"),
)
CARD_SHA256 = "39e96252229f5a3d0141dc81afb65a36fd205461ac21e5b70f2cd1248ef0082c"
# The Whisper MIT text, copyright statement and model-card caution, exactly as
# faster-whisper-small-en and faster-whisper-medium-en carry them.
LICENCE_SHA256 = "b5d65a59060e68c4ff940e1eddfa6f94b2d68fdf58ed7f4dd57721c997e35e9d"
STATEMENTS = (("whisper-notice-copyright", "94536c807e7ad8257102a5db0496db0bf1753fc8b32cba9188e337d9796db7d0"),)
ADVISORIES = (("whisper-card-caution", "0e9d0d19fa02b8f246d9902d93a2b0b0fac7cb07a518257ffa7d102d1c37c638"),)
# The owner's determination, kept with its evidence outside this repository.
OWNER_RECORD = ("licence-evidence-whisper-large-v3-2026-11-08/OWNER-DETERMINATION-whisper-large-v3.md",
                3218, "8d8c1cf3648b52e13ae0a55aee9bb23c295dcb3619e89dcf3f50717c2fced311")


def generate_whisper_large_v3_records(directory):
    raw = (directory / "determinations-whisper-large-v3.json").read_bytes()
    pin = load_pin(directory, "determinations-whisper-large-v3.sha256")
    if sha256_hex(raw) != pin:
        raise ValueError("Whisper large-v3 determination pin mismatch")
    data = load_json_object(raw, label="Whisper large-v3 determination")
    if (data.get("schema") != "kilix.license.whisper-large-v3-determination/v1"
            or len(data.get("records", [])) != 1):
        raise ValueError("unsupported Whisper large-v3 determination")
    authority = data.get("authority") or {}
    files = tuple((f.get("path"), f.get("bytes"), f.get("sha256")) for f in authority.get("files", []))
    if (authority.get("repository"), authority.get("revision"), files) != (REPOSITORY, REVISION, FILES):
        raise ValueError("unexpected Whisper large-v3 upstream binding")
    if authority.get("card_sha256") != CARD_SHA256 or authority.get("card_licence_line") != "license: mit":
        raise ValueError("unexpected Whisper large-v3 model card")
    if tuple((authority.get("owner_record") or {}).get(k)
             for k in ("path", "bytes", "sha256")) != OWNER_RECORD:
        raise ValueError("Whisper large-v3 terms lack the owner's determination")
    if authority.get("licence_sha256") != LICENCE_SHA256:
        raise ValueError("Whisper large-v3 licence is not displayed")
    record = LicenseRecord.from_mapping(dict(data["records"][0], determinations_sha256=pin))
    if record.id != MODEL_ID or record.licence_text_id != "kilix/config/model_notices#whisper":
        raise ValueError("unexpected Whisper large-v3 licence identity")
    if (record.licensor != "OpenAI; SYSTRAN" or record.licence_ids != ("MIT",)
            or record.decision_class != "affirmative"):
        raise ValueError("unexpected Whisper large-v3 licence classification")
    if record.text_sha256 != LICENCE_SHA256 or record.binding_conditions or record.components:
        raise ValueError("unexpected Whisper large-v3 terms or scope")
    if tuple((s.id, s.text_sha256) for s in record.statements) != STATEMENTS:
        raise ValueError("Whisper large-v3 must carry the Whisper copyright statement")
    if tuple((a.id, a.text_sha256) for a in record.advisories) != ADVISORIES:
        raise ValueError("Whisper large-v3 must carry the Whisper model card caution")
    for digest in (LICENCE_SHA256, *(d for _, d in STATEMENTS), *(d for _, d in ADVISORIES)):
        load_text_file(directory / "texts", digest, record.id)
    return [record]
