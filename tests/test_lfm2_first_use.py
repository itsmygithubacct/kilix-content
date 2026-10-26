"""LFM2's actual terms and notices through the offline first-use installer."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest import mock

from fake_store import FakeStore
from kilix_content.first_use import install_with_agreement, needs_agreement, present_asset
from kilix_content.install import Installer, InstallError
from kilix_content.model import AssetSpec, CatalogError
from kilix_license import load_determined_records, load_determined_texts, typed_agreement_line

ROOT=Path(__file__).resolve().parents[1]
module_spec=importlib.util.spec_from_file_location('lfm2_asset_generator',ROOT/'tools/generate_upstream_records.py')
generator=importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(generator)


class LFM2FirstUseTests(unittest.TestCase):
    def setUp(self):
        self.scratch=tempfile.TemporaryDirectory(prefix='kilix-lfm2-first-use-')
        self.addCleanup(self.scratch.cleanup)
        root=Path(self.scratch.name)
        self.records=load_determined_records()
        self.record=self.records.by_id('lfm2-kilix-commands')
        self.texts=load_determined_texts(root/'texts')
        self.store=FakeStore(root/'fixture-receipts')
        self.installer=Installer(str(root/'installed'))
        self.supplied=root/'supplied';self.supplied.mkdir()
        model=b'non-executable fixture weights'
        version='lfm2-kilix-commands-20261023-v1'
        url='https://github.com/itsmygithubacct/kilix-needle/releases/download/'+version+'/'+version+'.tar.gz'
        pin={'id':'lfm2-kilix-commands','license_record_id':'lfm2-kilix-commands',
             'provider':'kilix-needle','consumer_schema':'kilix.commands.model/v1',
             'version':version,'archive_url':url,'archive_bytes':1,'archive_sha256':'0'*64,
             'format':'tar','root':'fixture',
             'provenance':{'project':'itsmygithubacct/kilix-needle','revision':'1'*40,'original_url':url},
             'members':[{'path':'model.gguf','bytes':len(model),'sha256':hashlib.sha256(model).hexdigest()}]}
        self.spec=AssetSpec.from_mapping(generator.build_archive_asset(pin))
        (self.supplied/'model.gguf').write_bytes(model)
        for member in self.spec.files:
            if member.path.startswith('notices/'):
                destination=self.supplied/member.path;destination.parent.mkdir(exist_ok=True)
                destination.write_bytes(self.texts.get(member.sha256))

    def add_producer_notice(self):
        payload=b'Pinned producer notice fixture.\n'
        member={'path':'notices/PRODUCER.txt','bytes':len(payload),
                'sha256':hashlib.sha256(payload).hexdigest()}
        with self.assertRaises(FileNotFoundError):
            self.texts.get(member['sha256'])
        value=self.spec.to_mapping()
        value['files'].append(member)
        value['sizes']['installed_bytes']+=len(payload)
        value['sizes']['temporary_bytes']+=len(payload)
        self.spec=AssetSpec.from_mapping(value)
        (self.supplied/member['path']).write_bytes(payload)

    def install_archive(self, *, corrupt_notice=False):
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w:gz') as archive:
            for member in self.spec.files:
                payload=(self.supplied/member.path).read_bytes()
                if corrupt_notice and member.path=='notices/LICENSE-LFM.txt':
                    payload=b'changed licence'
                entry=tarfile.TarInfo('fixture/'+member.path)
                entry.size=len(payload)
                archive.addfile(entry,io.BytesIO(payload))
        payload=data.getvalue()
        value=self.spec.to_mapping()
        value['source']['archive_bytes']=len(payload)
        value['source']['archive_sha256']=hashlib.sha256(payload).hexdigest()
        value['sizes']['download_bytes']=len(payload)
        value['sizes']['temporary_bytes']=len(payload)+value['sizes']['installed_bytes']
        self.spec=AssetSpec.from_mapping(value)

        def fetch(url, destination, **kwargs):
            self.assertEqual(url,self.spec.url)
            self.assertEqual(kwargs['expected_bytes'],len(payload))
            self.assertEqual(kwargs['expected_sha256'],hashlib.sha256(payload).hexdigest())
            Path(destination).write_bytes(payload)

        with mock.patch('kilix_content.install.fetch_exact',side_effect=fetch):
            return install_with_agreement(self.spec,installer=self.installer,store=self.store,
                records=self.records,texts=self.texts,
                typed_text=typed_agreement_line(self.record),screen=io.BytesIO())

    def test_archive_reuses_exact_notices_including_a_pinned_producer_notice(self):
        self.add_producer_notice()
        self.assertIsNotNone(self.install_archive())
        destination=Path(self.installer.asset_destination(self.spec))
        for member in self.spec.files:
            self.assertEqual((destination/member.path).read_bytes(),
                             (self.supplied/member.path).read_bytes())

    def test_conflicting_bundled_notice_is_refused_not_replaced(self):
        with self.assertRaises(InstallError):
            self.install_archive(corrupt_notice=True)
        self.assertFalse(Path(self.installer.asset_destination(self.spec)).exists())

    def test_existing_notice_symlink_is_refused(self):
        notice=self.supplied/'notices/LICENSE-LFM.txt'
        target=self.supplied/'original-licence'
        notice.rename(target)
        notice.symlink_to(target)
        with self.assertRaises(InstallError):
            self.installer._write_notices(self.spec,str(self.supplied),self.texts)

    def test_offline_bundle_preserves_its_extra_pinned_producer_notice(self):
        self.add_producer_notice()
        self.assertIsNotNone(self.install(typed_text=typed_agreement_line(self.record),screen=io.BytesIO()))
        destination=Path(self.installer.asset_destination(self.spec))
        self.assertEqual((destination/'notices/PRODUCER.txt').read_bytes(),
                         (self.supplied/'notices/PRODUCER.txt').read_bytes())

    def test_offline_bundle_rejects_a_changed_producer_notice(self):
        self.add_producer_notice()
        (self.supplied/'notices/PRODUCER.txt').write_bytes(b'changed')
        with self.assertRaises(InstallError):
            self.install(typed_text=typed_agreement_line(self.record),screen=io.BytesIO())
        self.assertFalse(Path(self.installer.asset_destination(self.spec)).exists())

    def install(self,**kwargs):
        return install_with_agreement(self.spec,installer=self.installer,store=self.store,
            records=self.records,texts=self.texts,supplied=str(self.supplied),**kwargs)

    def test_full_terms_and_modification_notice_are_displayed_before_agreement(self):
        screen=present_asset(self.spec,self.record,self.texts,receipts=self.store,
                             records=self.records,supplied=self.supplied)
        self.assertIn(self.texts.get(self.record.text_sha256),screen)
        self.assertIn(b'Commercial Use Limitation',screen)
        self.assertIn(b'Liquid',screen)
        self.assertIn(self.texts.get(next(s.text_sha256 for s in self.record.statements
                                        if s.id=='modified-model')),screen)
        self.assertTrue(needs_agreement(self.spec,records=self.records,store=self.store))
        self.assertIsNone(self.install(typed_text=None,decline=True,screen=io.BytesIO()))
        self.assertEqual(list(self.store.root.glob('*.json')),[])
        self.assertFalse(Path(self.installer.asset_destination(self.spec)).exists())

    def test_fixture_agreement_imports_exact_notices_and_bytes_without_a_download(self):
        result=self.install(typed_text=typed_agreement_line(self.record),screen=io.BytesIO())
        self.assertIsNotNone(result)
        self.assertFalse(needs_agreement(self.spec,records=self.records,store=self.store))
        destination=Path(self.installer.asset_destination(self.spec))
        for member in self.spec.files:
            self.assertEqual((destination/member.path).read_bytes(),(self.supplied/member.path).read_bytes())
        self.assertEqual(len(list(self.store.root.glob('*.json'))),1)

    def test_corrupt_offline_weights_do_not_install(self):
        (self.supplied/'model.gguf').write_bytes(b'changed')
        with self.assertRaises(InstallError):
            self.install(typed_text=typed_agreement_line(self.record),screen=io.BytesIO())
        self.assertFalse(Path(self.installer.asset_destination(self.spec)).exists())

    def test_owned_derivative_route_cannot_be_reused_for_other_models_or_hosts(self):
        changes=[(('id',),'another-model'),(('provider',),'another-provider'),
                 (('version',),'latest'),(('compatibility','consumer_schema'),'another-schema'),
                 (('source','provenance','project'),'another/project'),
                 (('source','provenance','revision'),'main'),
                 (('licenses',0,'id'),'apache-2.0')]
        url=self.spec.source_url
        changes += [(('source',field),bad) for field in ('url',) for bad in (
            url.replace('/kilix-needle/','/kilix-content/'),url+'?token=fixture',
            url+'#fragment',url.replace('/download/','/download/../'))]
        changes += [(('source','provenance','original_url'),url.replace('/kilix-needle/','/kilix-content/'))]
        for keys,value in changes:
            mapping=self.spec.to_mapping();target=mapping
            for key in keys[:-1]:target=target[key]
            target[keys[-1]]=value
            with self.subTest(keys=keys,value=value),self.assertRaises(CatalogError):
                AssetSpec.from_mapping(mapping)
