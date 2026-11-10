"""Production catalog/receipt/notice contract for unchanged upstream Basic Pitch."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import kilix_content as api
import kilix_license as lic
from kilix_license.agreement import STANDARD_POLICY

ID='basic-pitch-icassp-2022-onnx'
MODEL_SHA='2c3c1d144bfa61ad236e92e169c13535c880469a12a047d4e73451f2c059a0ec'
ROOT=Path(__file__).resolve().parents[1]

class BasicPitchAssetTests(unittest.TestCase):
    def test_verified_catalog_adds_one_asset_preserving_all_previous_records(self):
        catalog=api.verified_packaged_catalog();spec=catalog.require_asset(ID)
        self.assertEqual(spec.provider,'kilix-playalong')
        self.assertEqual(spec.consumer_schema,'kilix.playalong.basic-pitch/v1')
        self.assertEqual(spec.version,'9991303bba609a3b93089d13ec80d1d495083596')
        self.assertEqual({f.path:(f.bytes,f.sha256) for f in spec.files},{
            'models/nmp.onnx':(230444,MODEL_SHA),
            'notices/LICENSE-apache-2.0.txt':(11384,'929c910bae2152fa87199a5d0660e09263419b7eee6d4b301d05ee2aaf211c37'),
            'notices/NOTICE-basic-pitch.txt':(1034,'b810e55c0e3b520fabb45fc2ccc74880187bf84e309971968541cc812dcde905')})
        before=json.loads(subprocess.check_output(['git','show','bc7ab69d6e0089729c7113b58563f3f0f0186301:src/kilix_content/catalog/plebian.json'],cwd=ROOT))
        after=json.loads((ROOT/'src/kilix_content/catalog/plebian.json').read_bytes())
        self.assertEqual(len(after['assets']),47)
        # Command-model releases have their own exact preservation contract.
        for document in (before, after):
            document['assets']=[a for a in document['assets']
                                if a['id'] not in (ID, 'paradee-8m-v1.2', 'en-core-web-sm-3.8.0', 'pp-ocrv6-small-det', 'pp-ocrv6-small-rec', 'qwen-0.8b-no-loop-02', 'faster-whisper-medium-en', 'demucs-htdemucs-6s', 'faster-whisper-large-v3',
                                              'lfm2-kilix-commands', 'lfm3-kilix-commands')]
        # Asset receipts must survive unrelated application pin updates.
        # Exact app/catalog delta scope is audited separately in the handoff.
        self.assertEqual(before['assets'],after['assets'])
        self.assertEqual(before['schema_version'],after['schema_version'])
        record=lic.load_determined_records().by_digest(spec.licenses[0].record_digest)
        self.assertEqual(record.id,ID);self.assertTrue(lic.standard_policy_eligible(record))

    @unittest.skipUnless(os.environ.get('BASIC_PITCH_SUPPLIED_MODEL'),'exact external upstream model file not provided')
    def test_real_supplied_bytes_policy_receipt_notices_and_refusals(self):
        source=Path(os.environ['BASIC_PITCH_SUPPLIED_MODEL']);raw=source.read_bytes()
        self.assertEqual(len(raw),230444);self.assertEqual(hashlib.sha256(raw).hexdigest(),MODEL_SHA)
        catalog=api.verified_packaged_catalog();spec=catalog.require_asset(ID)
        records=lic.load_determined_records();record=records.by_digest(spec.licenses[0].record_digest)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);store=lic.ReceiptStore(root/'receipts');texts=lic.load_determined_texts(root/'texts')
            supplied=root/'supplied';(supplied/'models').mkdir(parents=True);(supplied/'models/nmp.onnx').write_bytes(raw)
            installer=api.Installer(str(root/'apps'))
            with self.assertRaises(lic.CoverageRefused):
                installer.ensure_supplied_asset(spec,supplied=supplied,store=store,records=records,notices=texts)
            self.assertFalse(Path(installer.asset_destination(spec)).exists())
            fixtures=ROOT/'tests/data/receipts-d8e2c40a'
            for path in fixtures.glob('*.json'):shutil.copyfile(path,store.root/path.name)
            old={q.name:q.read_bytes() for q in store.root.glob('*.json')};self.assertEqual(len(old),22)
            # Actual standard distribution policy; no typed answer, owner claim,
            # fake receipt implementation or monkeypatched coverage routine.
            agreement=lic.capture_standard_policy(record)
            self.assertIsNone(agreement.typed_text)
            from kilix_content.receipt import catalog_sha256,release_digest
            receipt=lic.receipt_from_agreement(record,agreement,manifest_digest=spec.manifest_digest,catalogue_digest=catalog_sha256(),release_digest=release_digest())
            self.assertIn(STANDARD_POLICY,receipt.statement_digests);store.write(receipt)
            lic.require(lic.AssetRef(ID,record.digest,spec.manifest_digest),records=records,store=store)
            installer.ensure_supplied_asset(spec,supplied=supplied,store=store,records=records,notices=texts)
            installed=Path(installer.asset_destination(spec))
            for f in spec.files:
                content=(installed/f.path).read_bytes();self.assertEqual(len(content),f.bytes);self.assertEqual(hashlib.sha256(content).hexdigest(),f.sha256)
            for name,content in old.items():self.assertEqual((store.root/name).read_bytes(),content)
            with self.assertRaises(lic.CoverageRefused):lic.require(lic.AssetRef(ID,record.digest,'0'*64),records=records,store=store)
            (supplied/'models/nmp.onnx').write_bytes(b'wrong model')
            other=api.Installer(str(root/'other-apps'))
            with self.assertRaises(api.InstallError):other.ensure_supplied_asset(spec,supplied=supplied,store=store,records=records,notices=texts)
            self.assertFalse(Path(other.asset_destination(spec)).exists())
            self.assertEqual((installed/'models/nmp.onnx').read_bytes(),raw)
            if os.environ.get('BASIC_PITCH_RESULT'):
                result={'status':'pass','asset_id':ID,'manifest_digest':spec.manifest_digest,'record_digest':record.digest,'model_sha256':MODEL_SHA,'provider':spec.provider,'consumer_schema':spec.consumer_schema,'version':spec.version,'installed_files':{f.path:f.sha256 for f in spec.files},'old_fixture_receipts_preserved':len(old),'policy_receipt_sha256':hashlib.sha256(receipt.to_bytes()).hexdigest(),'missing_receipt_refused':True,'wrong_manifest_refused':True,'wrong_model_refused':True,'typed_owner_consent_claimed':False,'model_execution':False}
                Path(os.environ['BASIC_PITCH_RESULT']).write_text(json.dumps(result,indent=2)+'\n')
