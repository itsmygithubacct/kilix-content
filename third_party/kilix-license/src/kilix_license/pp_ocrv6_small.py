"""Separately pinned terms for PaddlePaddle's PP-OCRv6 small OCR models.

The owner determined both ONNX exports on 2026-11-10: Apache-2.0, "note the
reality". The grant is each model card's "license: apache-2.0" line. Neither
repository has a LICENSE or NOTICE file, each card's licence badge links to a
LICENSE file that does not exist, and no copyright holder is named; the
records name the publishing organization, PaddlePaddle, and show Debian's
Apache-2.0 text with a statement that says so. kilix-pdf-conversion's page OCR
reads them, and the image ships them. They live in their own family so that
no release record digest moves. This file does not fetch the models.
"""
from .digest import sha256_hex, load_json_object
from .generate import load_pin, load_text_file
from .records import LicenseRecord

DETECTOR = "pp-ocrv6-small-det"
RECOGNISER = "pp-ocrv6-small-rec"
MODEL_IDS = (DETECTOR, RECOGNISER)
MODELS = (
    (DETECTOR, "https://huggingface.co/PaddlePaddle/PP-OCRv6_small_det_onnx",
     "28fe5895c24fd108c19eb3e8479f4ab385fbfc62",
     (("inference.onnx", 9880512, "d73e0058b7a8086bbd57f3d10b8bcd4ff95363f67e06e2762b5e814fe9c9410e"),),
     (16076, "e9403667f0f92055d8ce9e73a2beb1002fc489d9342697db74039eb7178bb5fb")),
    (RECOGNISER, "https://huggingface.co/PaddlePaddle/PP-OCRv6_small_rec_onnx",
     "b8f84f0b80c529de40b4fbb3544b84fa7233a513",
     (("inference.onnx", 21159378, "5435fd747c9e0efe15a96d0b378d5bd157e9492ed8fd80edf08f30d02fa24634"),
      ("inference.yml", 150579, "ab078671bb49f06228eadccd34f1bb501e157f7a047095ffb943ba81512c77d1")),
     (16585, "7d46dbd183ac09bd5a2e6b4577dcb29240751b1c00eb6813eca308d529f86806")),
)
LICENSOR = "PaddlePaddle"
LICENCE_TEXT_ID = "debian/common-licenses/Apache-2.0"
LICENCE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
# What the cards do and do not say, shown with the licence.
STATEMENTS = (("pp-ocrv6-card-only-grant", "d10106e0139030f2ea1f330c9a165c418114909d32838719f2aa35cf5d9c95d6"),)
# The owner's determination, kept with its evidence outside this repository.
OWNER_RECORD = ("licence-evidence-pp-ocrv6-small-2026-11-10/OWNER-DETERMINATION-pp-ocrv6-small.md",
                4431, "733df4a6c6ce287cc2a066ddd1faf8aba35010497fba31cf78de31d30cea8f85")


def _binding(model):
    files = tuple((f.get("path"), f.get("bytes"), f.get("sha256")) for f in model.get("files", []))
    return (model.get("id"), model.get("repository"), model.get("revision"), files,
            (model.get("card_bytes"), model.get("card_sha256")))


def generate_pp_ocrv6_small_records(directory):
    raw = (directory / "determinations-pp-ocrv6-small.json").read_bytes()
    pin = load_pin(directory, "determinations-pp-ocrv6-small.sha256")
    if sha256_hex(raw) != pin:
        raise ValueError("PP-OCRv6 small determination pin mismatch")
    data = load_json_object(raw, label="PP-OCRv6 small determination")
    if (data.get("schema") != "kilix.license.pp-ocrv6-small-determination/v1"
            or len(data.get("records", [])) != len(MODEL_IDS)):
        raise ValueError("unsupported PP-OCRv6 small determination")
    authority = data.get("authority") or {}
    models = authority.get("models") or []
    if tuple(_binding(m) for m in models) != MODELS:
        raise ValueError("unexpected PP-OCRv6 small upstream binding")
    if any(m.get("card_licence_line") != "license: apache-2.0" for m in models):
        raise ValueError("unexpected PP-OCRv6 small model card")
    if authority.get("repository_licence_file", "absent") is not None:
        raise ValueError("PP-OCRv6 small must record that neither repository has a LICENSE file")
    if tuple((authority.get("owner_record") or {}).get(k)
             for k in ("path", "bytes", "sha256")) != OWNER_RECORD:
        raise ValueError("PP-OCRv6 small terms lack the owner's determination")
    if authority.get("licence_sha256") != LICENCE_SHA256:
        raise ValueError("PP-OCRv6 small licence is not displayed")
    records = []
    for expected, item in zip(MODEL_IDS, data["records"], strict=True):
        record = LicenseRecord.from_mapping(dict(item, determinations_sha256=pin))
        if record.id != expected or record.licence_text_id != LICENCE_TEXT_ID:
            raise ValueError("unexpected PP-OCRv6 small licence identity")
        if (record.licensor != LICENSOR or record.licence_ids != ("Apache-2.0",)
                or record.decision_class != "affirmative"):
            raise ValueError("unexpected PP-OCRv6 small licence classification")
        if (record.text_sha256 != LICENCE_SHA256 or record.binding_conditions
                or record.components or record.advisories):
            raise ValueError("unexpected PP-OCRv6 small terms or scope")
        if tuple((s.id, s.text_sha256) for s in record.statements) != STATEMENTS:
            raise ValueError("PP-OCRv6 small must state that the grant is the model card alone")
        records.append(record)
    for digest in (LICENCE_SHA256, *(d for _, d in STATEMENTS)):
        load_text_file(directory / "texts", digest, "pp-ocrv6-small")
    return records
