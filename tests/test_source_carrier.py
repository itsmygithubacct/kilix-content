"""Real offline source reconstruction and transaction refusal controls."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
from kilix_content.source_carrier import Carrier, SourceCarrierError, materialize_source
from kilix_content import ContentSpec, Installer, InstallError


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], stderr=subprocess.DEVNULL).decode().strip()


class SourceCarrierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.nodes = []
        self.child = self.make('child')
        self.parent = self.make('parent', self.child)
        self.manifest = self.root / 'manifest.json'; self.write()

    def make(self, name, child=None):
        p = self.root / name; p.mkdir(); git(p, 'init', '-q')
        git(p, 'config', 'user.name', 'itsmygithubacct')
        git(p, 'config', 'user.email', 'itsmygithubacct@users.noreply.github.com')
        (p / 'run').write_text('#!/bin/sh\nexit 0\n'); (p / 'run').chmod(0o755)
        links = {}
        if child:
            (p / '.gitmodules').write_text('[submodule "dep"]\n path = deps/child\n url = '+child['repository']+'\n')
            git(p, 'add', '.gitmodules'); git(p, 'update-index', '--add', '--cacheinfo', '160000,'+child['commit']+',deps/child')
            links['deps/child'] = {k: child[k] for k in ('repository', 'commit')}
        git(p, 'add', 'run'); git(p, 'commit', '-qm', 'Source fixture')
        commit = git(p, 'rev-parse', 'HEAD'); bundle = self.root / (name+'.bundle')
        git(p, 'bundle', 'create', str(bundle), '--all'); raw = bundle.read_bytes()
        node = {'repository':'https://example.test/'+name+'.git','commit':commit,'tree':git(p,'rev-parse','HEAD^{tree}'),'bundle':bundle.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'gitlinks':links}
        self.nodes.append(node); return node

    def write(self):
        raw = (json.dumps({'schema':'kilix.source-carrier/v1','nodes':self.nodes})+'\n').encode()
        self.manifest.write_bytes(raw); self.digest = hashlib.sha256(raw).hexdigest()

    def materialize(self, dest='out'):
        return materialize_source(self.parent['repository'],self.parent['commit'],self.root/dest,manifest_path=self.manifest,manifest_sha256=self.digest)

    def test_recursive_exact_source_no_remote_and_no_receipt_changes(self):
        receipts = self.root/'receipts'; receipts.write_bytes(b'untouched')
        self.assertTrue(self.materialize())
        out=self.root/'out'
        self.assertEqual(git(out,'rev-parse','HEAD'),self.parent['commit'])
        self.assertEqual(git(out/'deps/child','rev-parse','HEAD'),self.child['commit'])
        self.assertEqual(git(out,'status','--porcelain'),'')
        self.assertEqual(git(out,'rev-parse','--is-shallow-repository'),'false')
        self.assertTrue((out/'deps/child/.git').is_dir())
        self.assertEqual(receipts.read_bytes(),b'untouched')

    def test_changed_bundle_refused_without_destination(self):
        (self.root/self.parent['bundle']).write_bytes(b'bad')
        with self.assertRaises(SourceCarrierError): self.materialize()
        self.assertFalse((self.root/'out').exists())

    def test_missing_dependency_and_cycle_refused(self):
        self.nodes.remove(self.child); self.write()
        with self.assertRaises(SourceCarrierError): self.materialize()

    def test_symlink_bundle_and_parent_refused(self):
        b=self.root/self.parent['bundle']; saved=b.read_bytes(); b.unlink(); (self.root/'real').write_bytes(saved); b.symlink_to('real')
        with self.assertRaises(SourceCarrierError): self.materialize()

    def test_tree_and_gitlink_mismatch_refused(self):
        self.parent['tree']='0'*40; self.write()
        with self.assertRaises(SourceCarrierError): self.materialize()

    def test_paths_refused_and_duplicate_identity_refused(self):
        for path in ('../escape','/abs','a/../b','a\\b','.git/x'):
            self.parent['bundle']=path; self.write()
            with self.assertRaises(SourceCarrierError): self.materialize()

    def test_digest_and_unlisted_ref_refused(self):
        with self.assertRaises(SourceCarrierError):
            materialize_source(self.parent['repository'],'0'*40,self.root/'out',manifest_path=self.manifest,manifest_sha256=self.digest)
        with self.assertRaises(SourceCarrierError):
            materialize_source(self.parent['repository'],self.parent['commit'],self.root/'out',manifest_path=self.manifest,manifest_sha256='0'*64)

    def test_existing_destination_unchanged(self):
        out=self.root/'out'; out.mkdir(); (out/'choice').write_bytes(b'keep')
        with self.assertRaises(SourceCarrierError): self.materialize()
        self.assertEqual((out/'choice').read_bytes(),b'keep')

    def test_no_config_keeps_remote_path(self):
        with mock.patch('kilix_content.source_carrier.DEFAULT',self.root/'absent'):
            self.assertFalse(materialize_source('anything','anything',self.root/'out',env={}))

    def test_content_real_ensure_offline_and_failure_preserves_choice(self):
        env=dict(os.environ,KILIX_SOURCE_CARRIER_MANIFEST=str(self.manifest),KILIX_SOURCE_CARRIER_SHA256=self.digest)
        installer=Installer(str(self.root/'installed'),env=env)
        spec=ContentSpec(content_id='fixture',label='Fixture',kind='tool',icon='tool',description='Fixture',source_type='git',repository=self.parent['repository'].removesuffix('.git'),ref=self.parent['commit'],binary='run')
        executable=installer.ensure(spec); self.assertTrue(Path(executable).exists())
        before=Path(executable).read_bytes()
        (self.root/self.parent['bundle']).write_bytes(b'bad')
        self.assertEqual(installer.ensure(spec),executable)
        self.assertEqual(Path(executable).read_bytes(),before)

    def test_process_scoped_git_transport_clones_recursive_and_refuses_unlisted_remote(self):
        carrier=Carrier(self.manifest,self.digest)
        config=carrier.prepare_git(self.root/'pool')
        env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
        env.update(GIT_CONFIG_GLOBAL=config,GIT_CONFIG_NOSYSTEM='1',GIT_ALLOW_PROTOCOL='file',GIT_TERMINAL_PROMPT='0')
        dest=self.root/'clone'
        subprocess.run(['git','clone','--quiet','--recurse-submodules',self.parent['repository'],str(dest)],env=env,check=True,capture_output=True)
        self.assertEqual(git(dest,'rev-parse','HEAD'),self.parent['commit'])
        self.assertEqual(git(dest/'deps/child','rev-parse','HEAD'),self.child['commit'])
        denied=subprocess.run(['git','clone','https://example.test/absent',str(self.root/'absent')],env=env,capture_output=True)
        self.assertNotEqual(denied.returncode,0)
        self.assertIn(b"transport 'https' not allowed",denied.stderr)

    def test_cycle_duplicate_and_gitlink_mismatch_refused(self):
        self.parent['gitlinks']['deps/child']['commit']=self.parent['commit']
        self.parent['gitlinks']['deps/child']['repository']=self.parent['repository']
        self.write()
        with self.assertRaises(SourceCarrierError): self.materialize()
        self.parent['gitlinks']={};self.write()
        with self.assertRaises(SourceCarrierError): self.materialize()
        self.nodes.append(dict(self.parent));self.write()
        with self.assertRaises(SourceCarrierError): self.materialize()

    def test_symlink_directory_and_non_self_contained_bundle_refused(self):
        folder=self.root/'held';folder.mkdir()
        original=self.root/self.parent['bundle'];original.rename(folder/original.name)
        (self.root/'redirect').symlink_to(folder,target_is_directory=True)
        self.parent['bundle']='redirect/'+original.name;self.write()
        with self.assertRaises(SourceCarrierError): self.materialize()
        raw=b'# v2 git bundle\n-'+b'0'*40+b' required parent\n\nPACK'
        original.write_bytes(raw);self.parent['bundle']=original.name
        self.parent['bytes']=len(raw);self.parent['sha256']=hashlib.sha256(raw).hexdigest();self.write()
        with self.assertRaises(SourceCarrierError): self.materialize()

    def test_foreign_owned_pool_guard_is_scoped_to_exact_repositories(self):
        config=Path(Carrier(self.manifest,self.digest).prepare_git(self.root/'pool'))
        env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
        env.update(GIT_CONFIG_GLOBAL=str(config),GIT_CONFIG_NOSYSTEM='1',GIT_ALLOW_PROTOCOL='file',GIT_TERMINAL_PROMPT='0',GIT_TEST_ASSUME_DIFFERENT_OWNER='1')
        untrusted=self.root/'untrusted-config';untrusted.write_bytes(config.read_bytes())
        subprocess.run(['git','config','--file',str(untrusted),'--unset-all','safe.directory'],check=True)
        denied=subprocess.run(['git','clone','--quiet',self.parent['repository'],str(self.root/'denied')],env=dict(env,GIT_CONFIG_GLOBAL=str(untrusted)),capture_output=True)
        self.assertNotEqual(denied.returncode,0)
        self.assertIn(b'dubious ownership',denied.stderr)
        accepted=subprocess.run(['git','clone','--quiet','--recurse-submodules',self.parent['repository'],str(self.root/'accepted')],env=env,capture_output=True)
        self.assertEqual(accepted.returncode,0,accepted.stderr)

    def test_raw_object_types_refuse_annotated_tag_tree_and_blob_as_commit(self):
        repo=self.root/'parent'
        git(repo,'tag','-a','review-tag','-m','Annotated tag fixture')
        tag=git(repo,'rev-parse','review-tag')
        blob=git(repo,'rev-parse','HEAD:run')
        original=self.parent['commit']
        bundle=self.root/self.parent['bundle'];bundle.unlink()
        git(repo,'bundle','create',str(bundle),'--all')
        raw=bundle.read_bytes();self.parent['bytes']=len(raw);self.parent['sha256']=hashlib.sha256(raw).hexdigest()
        for wrong in (tag,self.parent['tree'],blob):
            self.parent['commit']=wrong;self.write()
            with self.subTest(object=wrong),self.assertRaises(SourceCarrierError):self.materialize()
            self.assertFalse((self.root/'out').exists())
        self.parent['commit']=original;self.parent['tree']=tag;self.write()
        with self.assertRaises(SourceCarrierError):self.materialize()

    def test_new_generation_failed_build_preserves_actual_selected_source(self):
        from dataclasses import replace
        import sys
        env=dict(os.environ,KILIX_SOURCE_CARRIER_MANIFEST=str(self.manifest),KILIX_SOURCE_CARRIER_SHA256=self.digest)
        installer=Installer(str(self.root/'installed'),env=env)
        spec=ContentSpec(content_id='fixture',label='Fixture',kind='tool',icon='tool',description='Fixture',source_type='git',repository=self.parent['repository'],ref=self.parent['commit'],binary='run')
        executable=Path(installer.ensure(spec));old_bytes=executable.read_bytes();old_commit=self.parent['commit']
        repo=self.root/'parent';(repo/'revision').write_text('next-generation')
        git(repo,'add','revision');git(repo,'commit','-qm','Next generation fixture')
        bundle=self.root/'next.bundle';git(repo,'bundle','create',str(bundle),'--all');raw=bundle.read_bytes()
        node=dict(self.parent,commit=git(repo,'rev-parse','HEAD'),tree=git(repo,'rev-parse','HEAD^{tree}'),bundle=bundle.name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        self.nodes.append(node);self.write();installer.env['KILIX_SOURCE_CARRIER_SHA256']=self.digest
        failing=replace(spec,ref=node['commit'],build=(sys.executable,'-c','raise SystemExit(29)'))
        with self.assertRaises(InstallError):installer.ensure(failing)
        self.assertEqual(executable.read_bytes(),old_bytes)
        self.assertEqual(git(executable.parent,'rev-parse','HEAD'),old_commit)
        self.assertEqual(installer.ensure(spec),str(executable))
