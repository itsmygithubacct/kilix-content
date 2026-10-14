import copy
import unittest
from kilix_content import verified_packaged_catalog
from kilix_content.model import AssetSpec,CatalogError
from kilix_license.catalog import load_determined_records

class DiarizationAssetTests(unittest.TestCase):
    def setUp(self):self.spec=verified_packaged_catalog().require_asset('kilix-diarization-cpu')
    def test_declared_inputs_output_population_licence_and_consumer_are_exact(self):
        self.assertEqual((self.spec.provider,self.spec.consumer_schema,self.spec.stream),
            ('kilix-transcribe','kilix.transcribe.diarization-runtime','F104'))
        self.assertEqual(self.spec.source_mode,'upstream-convert')
        self.assertEqual(self.spec.convert_sha256,'5b1a88b6f8d85826fabef804779c3372b42f3af21457fa48bd5c097c0686b2de')
        self.assertEqual(self.spec.convert_inputs[0].sha256,'220ad67ca923bef2fa91f2390c786097bf305bceb5e261d4af67b38e938e1079')
        self.assertEqual(self.spec.convert_inputs[0].provenance[1],'9403a6902bb58e3d5ae8c7e77c3422de279db2e0')
        population={x.path:x.sha256 for x in self.spec.files if not x.path.startswith('notices/')}
        self.assertEqual(set(population),{'diarize-runner','lib/libonnxruntime.so','segmentation.onnx','embedding.onnx','diarization.json'})
        self.assertEqual(population['embedding.onnx'],'7cfea971b2231ed7d7dd6324de1de33f8f9dbe65bbb30cf64b4b0b203b566292')
        self.assertFalse(any('bin' in x.path and x.path!='diarize-runner' for x in self.spec.files))
        self.assertEqual(self.spec.licenses[0].record_digest,load_determined_records().by_id(self.spec.asset_id).digest)
        self.assertIn('notices/pyannote-segmentation-3-0.txt',{x.path for x in self.spec.files})
        self.assertEqual(AssetSpec.from_mapping(self.spec.to_mapping()),self.spec)
    def test_each_external_input_needs_its_own_exact_provenance(self):
        for damage in ('missing','host','revision','token'):
            value=self.spec.to_mapping();item=value['source']['inputs'][0]
            if damage=='missing':item.pop('provenance')
            elif damage=='host':item['provenance']['original_url']='https://other.invalid/model.onnx'
            elif damage=='revision':item['provenance']['revision']='main'
            else:item['url']+='?token=secret'
            with self.subTest(damage=damage),self.assertRaises(CatalogError):AssetSpec.from_mapping(value)
    def test_modelscope_query_exception_cannot_accept_tags_tokens_duplicate_keys_or_navigation(self):
        base=self.spec.convert_url
        for changed in (base.replace(self.spec.version,'main'),base+'&token=x',base+'&Revision='+self.spec.version,
                base.replace('campplus_voxceleb.bin','../other.bin'),base.replace('www.modelscope.cn','other.invalid')):
            value=self.spec.to_mapping();value['source']['input']['url']=changed
            with self.subTest(url=changed),self.assertRaises(CatalogError):AssetSpec.from_mapping(value)
