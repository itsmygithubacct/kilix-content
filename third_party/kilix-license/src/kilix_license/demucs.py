"""Separately pinned terms for the Demucs htdemucs_6s pretrained weights.

The owner determined these terms on 2026-11-08, adopting the builder's reading
of the upstream evidence below with its two gaps stated (no weights-specific
licence; training data terms not established). The artifact is Meta's original release of the six-source Hybrid Transformer
Demucs model: the one weights file that the pinned Demucs source (adefossez/
demucs at eeac1d15) names in demucs/remote/files.txt and checks by sha256
prefix. Its htdemucs_6s.yaml names that single model with default weights, so
the bag definition is evidence here, not part of the artifact. Demucs is released under the
MIT licence (README "License" and LICENSE at that commit; relicensed from
CC BY-NC 4.0 on 2020-04-13). No separate licence is published for the
weights. The record shows that MIT text, the one Meta's EnCodec converter
record already carries. It lives in its own family so that no existing record
digest moves. On 2026-11-08 the owner also decided its distribution: from
Plebian-OS 0.2.3 RC5 the weights ship in the image with the MIT text beside
them and install by default for Kilix Playalong unless declined. This file does
not fetch the weights.
"""
from .digest import sha256_hex, load_json_object
from .generate import load_pin, load_text_file
from .records import LicenseRecord

MODEL_ID = "demucs-htdemucs-6s"
REPOSITORY = "https://github.com/adefossez/demucs"
REVISION = "eeac1d15891af95b1288d2884b95baa3e5baa96c"
WEIGHTS_URL = "https://dl.fbaipublicfiles.com/demucs/hybrid_transformer/5c90dfd2-34c22ccb.th"
FILES = (
    ("5c90dfd2-34c22ccb.th", WEIGHTS_URL, 54996327,
     "34c22ccb381c6f9fdbf324f04e1e2fe21aaaf293f5ded163a162697ff9a02ddd"),
)
BAG = ("demucs/remote/htdemucs_6s.yaml", 21,
       "207405151270af8fd81c2373c25d27950916682ac91dca7884a11ce13dad6f58", "models: ['5c90dfd2']")
FILES_LIST_SHA256 = "7258eee911e5963e6270983d7072832e90e1ed96b25bb26aadf12f9867109bf9"
README_SHA256 = "59ab8a3595cd5ec8dd853821ca2b377804f397be8467a082920f1c44e0d59d35"
README_LICENCE_LINE = "Demucs is released under the MIT license as found in the [LICENSE](LICENSE) file."
RELICENSING_COMMIT = "25dada5a68a7ceecd831a113e5712512312e4a3f"
# Meta's MIT text, byte for byte the demucs LICENSE at REVISION.
LICENCE_SHA256 = "cf9b17822d1fcd4ff32ccbe14183386fb3adf6f2ff92dc184130823f7fc28173"
LICENSOR = "Meta Platforms, Inc. and affiliates"
LICENCE_TEXT_ID = "github.com/adefossez/demucs/LICENSE"
# The owner's determination, kept with its evidence outside this repository.
OWNER_RECORD = ("licence-evidence-demucs-htdemucs-6s-2026-11-08/OWNER-DETERMINATION-demucs-htdemucs-6s.md",
                3506, "c58b90a793b5a0866253d5351de0cc61000f05835daf6736a0ae3a2e2e22def0")
# The owner's 2026-11-08 distribution decision: the weights also ship in the
# Plebian-OS image (MIT notice beside them) and install by default for Kilix
# Playalong unless declined. The terms above are unchanged by it.
DISTRIBUTION_RECORD = (
    "licence-evidence-demucs-htdemucs-6s-2026-11-08/OWNER-DISTRIBUTION-demucs-htdemucs-6s-2026-11-08.md",
    2683, "70c4baa8d8df919ddf0023ab12a8ef7edf43e84f3ff9895e6493c6a464067322")


def generate_demucs_records(directory):
    raw = (directory / "determinations-demucs.json").read_bytes()
    pin = load_pin(directory, "determinations-demucs.sha256")
    if sha256_hex(raw) != pin:
        raise ValueError("Demucs determination pin mismatch")
    data = load_json_object(raw, label="Demucs determination")
    if (data.get("schema") != "kilix.license.demucs-determination/v1"
            or len(data.get("records", [])) != 1):
        raise ValueError("unsupported Demucs determination")
    authority = data.get("authority") or {}
    files = tuple((f.get("path"), f.get("url"), f.get("bytes"), f.get("sha256"))
                  for f in authority.get("files", []))
    if (authority.get("repository"), authority.get("revision"), files) != (REPOSITORY, REVISION, FILES):
        raise ValueError("unexpected Demucs upstream binding")
    if (authority.get("files_list_sha256") != FILES_LIST_SHA256
            or tuple((authority.get("bag_definition") or {}).get(k)
                     for k in ("path", "bytes", "sha256", "text")) != BAG
            or authority.get("readme_sha256") != README_SHA256
            or authority.get("readme_licence_line") != README_LICENCE_LINE
            or (authority.get("relicensing") or {}).get("commit") != RELICENSING_COMMIT):
        raise ValueError("unexpected Demucs licence evidence")
    if tuple((authority.get("owner_record") or {}).get(k)
             for k in ("path", "bytes", "sha256")) != OWNER_RECORD:
        raise ValueError("Demucs terms lack the owner's determination")
    if tuple(((authority.get("distribution") or {}).get("owner_record") or {}).get(k)
             for k in ("path", "bytes", "sha256")) != DISTRIBUTION_RECORD:
        raise ValueError("Demucs distribution lacks the owner's decision")
    if authority.get("licence_sha256") != LICENCE_SHA256:
        raise ValueError("Demucs licence is not displayed")
    record = LicenseRecord.from_mapping(dict(data["records"][0], determinations_sha256=pin))
    if record.id != MODEL_ID or record.licence_text_id != LICENCE_TEXT_ID:
        raise ValueError("unexpected Demucs licence identity")
    if (record.licensor != LICENSOR or record.licence_ids != ("MIT",)
            or record.decision_class != "affirmative"):
        raise ValueError("unexpected Demucs licence classification")
    if (record.text_sha256 != LICENCE_SHA256 or record.binding_conditions or record.components
            or record.advisories or record.statements):
        raise ValueError("unexpected Demucs terms or scope")
    load_text_file(directory / "texts", LICENCE_SHA256, record.id)
    return [record]
