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
from kilix_license.errors import CoverageRefused

ROOT=Path(__file__).resolve().parents[1]
module_spec=importlib.util.spec_from_file_location('lfm2_asset_generator',ROOT/'tools/generate_upstream_records.py')
generator=importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(generator)


class LFM2FirstUseTests(unittest.TestCase):
    asset_id = 'lfm2-kilix-commands'
    notice_id = 'modified-model'
    def setUp(self):
        self.scratch=tempfile.TemporaryDirectory(prefix='kilix-lfm2-first-use-')
        self.addCleanup(self.scratch.cleanup)
        root=Path(self.scratch.name)
        self.records=load_determined_records()
        self.record=self.records.by_id(self.asset_id)
        self.texts=load_determined_texts(root/'texts')
        self.store=FakeStore(root/'fixture-receipts')
        self.installer=Installer(str(root/'installed'))
        self.supplied=root/'supplied';self.supplied.mkdir()
        model=b'non-executable fixture weights'
        version=self.asset_id+'-20261103-v1'
        url='https://github.com/itsmygithubacct/kilix-needle/releases/download/'+version+'/'+version+'.tar.gz'
        pin={'id':self.asset_id,'license_record_id':self.asset_id,
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

    def answer(self):
        # LFM2's terms are a notice (owner determination 2026-11-07) and take no
        # typed agreement; LFM3 still takes one.
        if self.record.expected_decision == 'record':
            return None
        return typed_agreement_line(self.record)

    def test_lfm2_terms_are_a_notice_and_take_no_typed_agreement(self):
        if self.asset_id != 'lfm2-kilix-commands':
            self.skipTest('LFM3 keeps its typed agreement')
        from kilix_license.errors import AgreementRequired
        self.assertEqual(self.record.expected_decision, 'record')
        with self.assertRaises(AgreementRequired):
            self.install(typed_text=typed_agreement_line(self.record), screen=io.BytesIO())
        self.assertEqual(list(self.store.root.glob('*.json')), [])
        self.assertIsNotNone(self.install(typed_text=None, screen=io.BytesIO()))
        receipt, = [__import__('json').loads(p.read_bytes()) for p in self.store.root.glob('*.json')]
        self.assertEqual(receipt['decision'], 'record')
        self.assertNotIn('yes', __import__('json').dumps(receipt))

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
                typed_text=self.answer(),screen=io.BytesIO())

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
        self.assertIsNotNone(self.install(typed_text=self.answer(),screen=io.BytesIO()))
        destination=Path(self.installer.asset_destination(self.spec))
        self.assertEqual((destination/'notices/PRODUCER.txt').read_bytes(),
                         (self.supplied/'notices/PRODUCER.txt').read_bytes())

    def test_offline_bundle_rejects_a_changed_producer_notice(self):
        self.add_producer_notice()
        (self.supplied/'notices/PRODUCER.txt').write_bytes(b'changed')
        with self.assertRaises(InstallError):
            self.install(typed_text=self.answer(),screen=io.BytesIO())
        self.assertFalse(Path(self.installer.asset_destination(self.spec)).exists())

    def install(self,**kwargs):
        return install_with_agreement(self.spec,installer=self.installer,store=self.store,
            records=self.records,texts=self.texts,supplied=str(self.supplied),**kwargs)

    def revised_model(self, payload=b'revised fixture weights'):
        value = self.spec.to_mapping()
        value['storage'] = 'versioned'
        model = next(item for item in value['files'] if item['path'] == 'model.gguf')
        delta = len(payload) - model['bytes']
        model.update(bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
        value['sizes']['installed_bytes'] += delta
        value['sizes']['temporary_bytes'] += delta
        self.spec = AssetSpec.from_mapping(value)
        (self.supplied/'model.gguf').write_bytes(payload)

    def test_versioned_update_preserves_legacy_install_and_rollback(self):
        old_spec = self.spec
        self.install(typed_text=self.answer(), screen=io.BytesIO())
        old_path = Path(self.installer.asset_destination(old_spec))
        original = (old_path/'model.gguf').read_bytes()
        self.revised_model()
        self.install(typed_text=self.answer(), screen=io.BytesIO())
        new_path = Path(self.installer.asset_destination(self.spec))
        self.assertNotEqual(old_path, new_path)
        self.assertEqual((old_path/'model.gguf').read_bytes(), original)
        self.assertEqual((new_path/'model.gguf').read_bytes(), (self.supplied/'model.gguf').read_bytes())
        # Rolling back the catalog reselects the old verified bytes and receipt.
        selected = self.installer.ensure_supplied_asset(old_spec, supplied='not-read',
            store=self.store, records=self.records, notices=self.texts)
        self.assertEqual(selected, (str(old_path),))

    def test_versioned_update_requires_its_own_manifest_receipt(self):
        self.install(typed_text=self.answer(), screen=io.BytesIO())
        old_path = Path(self.installer.asset_destination(self.spec))
        self.revised_model()
        self.assertTrue(needs_agreement(self.spec, records=self.records, store=self.store))
        with self.assertRaises(CoverageRefused):
            self.installer.ensure_supplied_asset(self.spec, supplied=str(self.supplied),
                store=self.store, records=self.records, notices=self.texts)
        self.assertTrue(old_path.is_dir())
        self.assertFalse(Path(self.installer.asset_destination(self.spec)).exists())

    def test_failed_versioned_install_preserves_previous_revision(self):
        self.revised_model(b'first versioned fixture')
        old_spec = self.spec
        self.install(typed_text=self.answer(), screen=io.BytesIO())
        old_path = Path(self.installer.asset_destination(old_spec))
        original = (old_path/'model.gguf').read_bytes()
        self.revised_model(b'second versioned fixture')
        (self.supplied/'model.gguf').write_bytes(b'corrupt replacement')
        with self.assertRaises(InstallError):
            self.install(typed_text=self.answer(), screen=io.BytesIO())
        self.assertFalse(Path(self.installer.asset_destination(self.spec)).exists())
        self.assertEqual((old_path/'model.gguf').read_bytes(), original)

    # --- a new delivery is built from the installed earlier one ---

    def delivery(self, *, extra):
        """A versioned delivery of the same model, with or without a file the next one drops."""
        value = self.spec.to_mapping()
        value['storage'] = 'versioned'
        payload = b'a runtime library the next delivery omits'
        present = any(item['path'] == 'runtime/extra.so' for item in value['files'])
        if extra and not present:
            value['files'].append({'path': 'runtime/extra.so', 'bytes': len(payload),
                                   'sha256': hashlib.sha256(payload).hexdigest()})
            (self.supplied/'runtime').mkdir(exist_ok=True)
            (self.supplied/'runtime/extra.so').write_bytes(payload)
            delta = len(payload)
        elif not extra and present:
            value['files'] = [item for item in value['files'] if item['path'] != 'runtime/extra.so']
            delta = -len(payload)
        else:
            delta = 0
        value['sizes']['installed_bytes'] += delta
        value['sizes']['temporary_bytes'] += delta
        self.spec = AssetSpec.from_mapping(value)
        return self.spec

    def earlier_then_next(self):
        earlier = self.delivery(extra=True)
        self.install(typed_text=self.answer(), screen=io.BytesIO())
        return Path(self.installer.asset_destination(earlier)), self.delivery(extra=False)

    def upstream(self, reports=None):
        return install_with_agreement(
            self.spec, installer=self.installer, store=self.store, records=self.records,
            texts=self.texts, typed_text=self.answer(), screen=io.BytesIO(),
            report=(reports.append if reports is not None else lambda _message: None))

    def test_a_new_delivery_is_installed_from_the_earlier_one_without_a_download(self):
        old_path, spec = self.earlier_then_next()
        before = {path.relative_to(old_path): path.read_bytes()
                  for path in old_path.rglob('*') if path.is_file()}
        self.assertEqual(self.installer.earlier_delivery(spec), str(old_path))
        self.assertTrue(needs_agreement(spec, records=self.records, store=self.store))
        reports = []
        with mock.patch('kilix_content.install.fetch_exact', side_effect=AssertionError('downloaded')):
            self.assertIsNotNone(self.upstream(reports))
        new_path = Path(self.installer.asset_destination(spec))
        self.assertNotEqual(new_path, old_path)
        self.assertEqual(sorted(str(path.relative_to(new_path)) for path in new_path.rglob('*') if path.is_file()),
                         sorted(member.path for member in spec.files))
        self.assertFalse((new_path/'runtime/extra.so').exists())
        self.assertTrue(any('earlier delivery' in line for line in reports), reports)
        # The earlier delivery is read, never changed, and stays selectable.
        self.assertEqual({path.relative_to(old_path): path.read_bytes()
                          for path in old_path.rglob('*') if path.is_file()}, before)

    def test_reuse_still_needs_the_new_manifests_own_receipt(self):
        _old_path, spec = self.earlier_then_next()
        with mock.patch('kilix_content.install.fetch_exact', side_effect=AssertionError('downloaded')), \
                self.assertRaises(CoverageRefused):
            self.installer.ensure_upstream_asset(spec, store=self.store, records=self.records,
                                                 notices=self.texts)
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

    def test_an_earlier_delivery_with_other_bytes_is_discarded_and_the_asset_is_downloaded(self):
        old_path, spec = self.earlier_then_next()
        model = old_path/'model.gguf'
        good = model.read_bytes()
        model.chmod(0o600)
        model.write_bytes(bytes(len(good)))          # same size, other bytes
        self.assertEqual(self.installer.earlier_delivery(spec), str(old_path))
        self.assertIsNotNone(self.install_archive())
        new_path = Path(self.installer.asset_destination(self.spec))
        self.assertEqual((new_path/'model.gguf').read_bytes(), good)
        self.assertEqual(model.read_bytes(), bytes(len(good)))

    def test_an_older_intact_delivery_is_used_when_the_newest_cannot_supply(self):
        import os, shutil
        old_path, spec = self.earlier_then_next()
        newer = old_path.parent/(self.asset_id + '--' + 'c'*64)
        shutil.copytree(old_path, newer)
        (newer/'model.gguf').chmod(0o600)
        (newer/'model.gguf').write_bytes(bytes((old_path/'model.gguf').stat().st_size))
        os.utime(old_path, ns=(1, 1))
        self.assertEqual(self.installer.earlier_deliveries(spec), [str(newer), str(old_path)])
        with mock.patch('kilix_content.install.fetch_exact', side_effect=AssertionError('downloaded')):
            self.assertIsNotNone(self.upstream())

    def test_a_link_put_in_place_of_the_found_directory_is_not_read(self):
        # The scan saw a directory; before it is read it becomes a link to a
        # tree outside the assets directory that holds the right bytes.
        import shutil
        old_path, spec = self.earlier_then_next()
        outside = Path(self.scratch.name)/'outside'
        found = self.installer.earlier_deliveries(spec)
        shutil.move(str(old_path), str(outside))
        old_path.symlink_to(outside)
        reports = []
        with mock.patch.object(self.installer, 'earlier_deliveries', return_value=found), \
                mock.patch.object(self.installer, '_populate_upstream_asset',
                                  side_effect=InstallError('would download')) as download, \
                self.assertRaises(InstallError):
            self.upstream(reports)
        download.assert_called_once()
        self.assertTrue(any('could not supply' in line for line in reports), reports)
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

    def test_what_is_not_an_earlier_delivery(self):
        old_path, spec = self.earlier_then_next()
        parent = old_path.parent
        # A file of another size, a missing file, a link, another asset, an unversioned asset.
        (old_path/'model.gguf').chmod(0o600)
        (old_path/'model.gguf').write_bytes(b'short')
        self.assertIsNone(self.installer.earlier_delivery(spec))
        (old_path/'model.gguf').unlink()
        self.assertIsNone(self.installer.earlier_delivery(spec))
        (old_path/'model.gguf').symlink_to(self.supplied/'model.gguf')
        self.assertIsNone(self.installer.earlier_delivery(spec))
        moved = parent/'elsewhere'
        (moved/'x').mkdir(parents=True)
        (moved/'model.gguf').write_bytes((self.supplied/'model.gguf').read_bytes())
        (parent/('other-asset--' + 'a'*64)).symlink_to(moved)
        (parent/(self.asset_id + '--' + 'b'*64)).symlink_to(moved)
        (parent/(self.asset_id + '--not-a-digest')).mkdir()
        self.assertIsNone(self.installer.earlier_delivery(spec))
        value = spec.to_mapping()
        value.pop('storage')                      # flat storage: one directory, no deliveries
        self.assertIsNone(self.installer.earlier_delivery(AssetSpec.from_mapping(value)))

    def test_versioned_storage_round_trips_and_refuses_unknown_layout(self):
        self.revised_model()
        value = self.spec.to_mapping()
        self.assertEqual(value['storage'], 'versioned')
        self.assertEqual(AssetSpec.from_mapping(value), self.spec)
        value['storage'] = '../elsewhere'
        with self.assertRaises(CatalogError):
            AssetSpec.from_mapping(value)

    def test_full_terms_and_modification_notice_are_displayed_before_agreement(self):
        screen=present_asset(self.spec,self.record,self.texts,receipts=self.store,
                             records=self.records,supplied=self.supplied)
        self.assertIn(self.texts.get(self.record.text_sha256),screen)
        self.assertIn(b'Commercial Use Limitation',screen)
        self.assertIn(b'Liquid',screen)
        self.assertIn(self.texts.get(next(s.text_sha256 for s in self.record.statements
                                        if s.id==self.notice_id)),screen)
        self.assertTrue(needs_agreement(self.spec,records=self.records,store=self.store))
        self.assertIsNone(self.install(typed_text=None,decline=True,screen=io.BytesIO()))
        self.assertEqual(list(self.store.root.glob('*.json')),[])
        self.assertFalse(Path(self.installer.asset_destination(self.spec)).exists())

    def test_fixture_agreement_imports_exact_notices_and_bytes_without_a_download(self):
        result=self.install(typed_text=self.answer(),screen=io.BytesIO())
        self.assertIsNotNone(result)
        self.assertFalse(needs_agreement(self.spec,records=self.records,store=self.store))
        destination=Path(self.installer.asset_destination(self.spec))
        for member in self.spec.files:
            self.assertEqual((destination/member.path).read_bytes(),(self.supplied/member.path).read_bytes())
        self.assertEqual(len(list(self.store.root.glob('*.json'))),1)

    def test_corrupt_offline_weights_do_not_install(self):
        (self.supplied/'model.gguf').write_bytes(b'changed')
        with self.assertRaises(InstallError):
            self.install(typed_text=self.answer(),screen=io.BytesIO())
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


class LFM3FirstUseTests(LFM2FirstUseTests):
    asset_id = "lfm3-kilix-commands"
    notice_id = "upstream-model"
