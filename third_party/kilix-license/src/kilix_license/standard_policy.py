"""Versioned distribution policy for standard licences without extra terms."""
import hashlib

from kilix_license.agreement import Agreement, STANDARD_POLICY, observe_capture
from kilix_license.errors import AgreementRequired


POLICY_TEXT = b"Standard licences without additional terms are authorized by distribution policy, not a typed user answer. Original licences and notices remain required.\n"
POLICY_SHA256 = hashlib.sha256(POLICY_TEXT).hexdigest()

STANDARD_IDS = frozenset({
    'Apache-2.0', 'MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'Zlib',
    'MPL-2.0', 'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0-only',
    'GPL-3.0-or-later', 'LGPL-2.1-only', 'LGPL-2.1-or-later',
    'LGPL-3.0-only', 'LGPL-3.0-or-later', 'CC0-1.0', 'CC-BY-4.0',
    'CC-BY-SA-4.0',
})


def standard_policy_eligible(record):
    """Unknown identifiers, extra conditions and component exceptions prompt.

    Classification uses the complete determined record, never a catalog label
    or a substring found in licence prose. Original documents remain required.
    """
    # The legacy component field also holds ordinary licence notices. Only
    # this reviewed, byte-pinned MIT notice is allowed through that field.
    ordinary_notices = {
        ('needle3-kilix-commands', 'cached-runtime',
         '831c057440d79f85a28362fd6765ccba24346e28343f1cecdb7eda7d1b479863'),
    }
    if record.binding_conditions or any(
        c.exception_text_sha256 and (record.id, c.id, c.exception_text_sha256)
        not in ordinary_notices for c in record.components
    ):
        return False
    if not record.licence_ids:
        return False
    if set(record.licence_ids) <= STANDARD_IDS:
        return True
    return (record.id == 'piper-en-us-kristin-medium'
            and record.licence_ids == ("Public domain, per the trainer's statement",))


def capture_standard_policy(record):
    """Record distribution-policy authorization, never a fabricated typed Yes."""
    if not standard_policy_eligible(record):
        raise AgreementRequired('licence has terms outside the standard distribution policy')
    observed = observe_capture()
    return Agreement(record.id, (), record.expected_decision, None,
                     record_digest=record.digest,
                     binding_condition_text_digests={}, acceptance=observed,
                     authorization_policy=STANDARD_POLICY)
