"""Digest-bound, source-only offline Git transport; also usable as a standalone CLI."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from urllib.parse import urljoin, urlsplit

DEFAULT = Path('/usr/share/plebian-os/source-carrier/manifest.json')


class SourceCarrierError(RuntimeError):
    """A configured source carrier failed; online fallback is forbidden."""


def _hex(value, size):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % size, value)


def _relative(value):
    if not isinstance(value, str) or '\\' in value or any(ord(c) < 32 for c in value):
        raise SourceCarrierError('invalid carrier path')
    if any(p in ('', '.', '..', '.git') for p in value.split('/')):
        raise SourceCarrierError('unsafe carrier path')
    return value


def _repository(value):
    if not isinstance(value, str):
        raise SourceCarrierError('invalid repository')
    u = urlsplit(value)
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.query or u.fragment:
        raise SourceCarrierError('repository must be a plain HTTPS identity')
    _relative(u.path.lstrip('/'))
    return value.removesuffix('.git').rstrip('/')


def _env():
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1', GIT_ALLOW_PROTOCOL='file')
    return env


def _git(directory, *args, ok=(0,)):
    result = subprocess.run(['git', '-c', 'gc.auto=0', '-c', 'maintenance.auto=false', '-c', 'pack.threads=2', '-c', 'index.threads=2', '-c', 'core.hooksPath=' + os.devnull,
                             '-c', 'core.autocrlf=false', '-C', str(directory), *args],
                            env=_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=180, check=False)
    if result.returncode not in ok:
        raise SourceCarrierError('offline Git failed: ' + ' '.join(args[:2]) + ': ' +
                                 result.stderr.decode(errors='replace')[-400:])
    return result.stdout


def _read(root, relative, limit):
    """Open every component beneath root without following symlinks."""
    parts = _relative(relative).split('/')
    handles = []
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        handles.append(fd)
        for part in parts[:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            handles.append(fd)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        handles.append(fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise SourceCarrierError('carrier input is not a bounded regular file')
        chunks = []; total = 0
        while True:
            block = os.read(fd, min(1024 * 1024, limit + 1 - total))
            if not block:
                break
            chunks.append(block); total += len(block)
            if total > limit:
                raise SourceCarrierError('carrier input grew beyond bound')
        return b''.join(chunks)
    finally:
        for fd in reversed(handles):
            os.close(fd)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise SourceCarrierError('duplicate manifest key')
        result[key] = value
    return result


class Carrier:
    def __init__(self, manifest, digest):
        self.path = Path(manifest).absolute()
        if not _hex(digest, 64):
            raise SourceCarrierError('missing valid manifest digest')
        raw = _read(self.path.parent, self.path.name, 16 * 1024 * 1024)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise SourceCarrierError('source manifest digest mismatch')
        data = json.loads(raw, object_pairs_hook=_pairs)
        if data.get('schema') != 'kilix.source-carrier/v1' or not isinstance(data.get('nodes'), list):
            raise SourceCarrierError('unsupported source manifest')
        self.nodes = {}
        declared_refs = {}
        if not 0 < len(data['nodes']) <= 4096:
            raise SourceCarrierError('invalid source node count')
        for node in data['nodes']:
            key = (_repository(node['repository']), node['commit'])
            if key in self.nodes or not _hex(node['commit'], 40) or not _hex(node['tree'], 40):
                raise SourceCarrierError('duplicate or invalid source identity')
            _relative(node['bundle'])
            if not _hex(node['sha256'], 64) or type(node['bytes']) is not int or not 0 < node['bytes'] <= 512 * 1024 * 1024:
                raise SourceCarrierError('invalid bundle binding')
            if not isinstance(node['gitlinks'], dict):
                raise SourceCarrierError('invalid gitlink map')
            paths = sorted(node['gitlinks'])
            for i, path in enumerate(paths):
                _relative(path)
                if any(path.startswith(other + '/') for other in paths[:i]):
                    raise SourceCarrierError('overlapping gitlinks')
                child = node['gitlinks'][path]
                _repository(child['repository'])
                if not _hex(child['commit'], 40):
                    raise SourceCarrierError('invalid dependency identity')
            refs = node.get('refs', {})
            if not isinstance(refs, dict) or len(refs) > 256:
                raise SourceCarrierError('invalid named ref map')
            for ref, binding in refs.items():
                if not isinstance(ref, str) or not re.fullmatch(r'refs/(heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]*', ref):
                    raise SourceCarrierError('unsafe named ref namespace')
                _relative(ref)
                if (not isinstance(binding, dict) or set(binding) != {'object', 'type'}
                        or not _hex(binding['object'], 40) or binding['type'] not in ('commit', 'tag')
                        or (ref.startswith('refs/heads/') and binding['type'] != 'commit')):
                    raise SourceCarrierError('invalid named ref binding')
                ref_key = (key[0], ref)
                identity = (binding['object'], binding['type'], node['commit'])
                if ref_key in declared_refs and declared_refs[ref_key] != identity:
                    raise SourceCarrierError('conflicting named ref bindings')
                declared_refs[ref_key] = identity
            self.nodes[key] = node
        visited = set()
        def visit(key, ancestors):
            if key in ancestors or len(ancestors) >= 32 or key not in self.nodes:
                raise SourceCarrierError('missing, cyclic or excessive source dependency')
            if key in visited:
                return
            for child in self.nodes[key]['gitlinks'].values():
                visit((_repository(child['repository']), child['commit']), ancestors | {key})
            visited.add(key)
        for key in self.nodes:
            visit(key, set())
        self.remaining_nodes = 10000

    def _populate(self, key, destination):
        self.remaining_nodes -= 1
        if self.remaining_nodes < 0:
            raise SourceCarrierError('source reconstruction exceeds node budget')
        if key not in self.nodes:
            raise SourceCarrierError('exact source is absent from configured carrier')
        node = self.nodes[key]
        raw = _read(self.path.parent, node['bundle'], node['bytes'])
        if len(raw) != node['bytes'] or hashlib.sha256(raw).hexdigest() != node['sha256']:
            raise SourceCarrierError('source bundle size/digest mismatch')
        header = raw.split(b'\n\n', 1)[0].splitlines()
        if not header or header[0] not in (b'# v2 git bundle', b'# v3 git bundle') or any(x.startswith(b'-') for x in header):
            raise SourceCarrierError('source bundle must be self-contained')
        destination.mkdir(parents=True)
        _git(destination, 'init', '--quiet')
        with tempfile.TemporaryDirectory(prefix='source-bundle-', dir=destination.parent) as tmp:
            bundle = Path(tmp) / 'verified.bundle'; bundle.write_bytes(raw)
            _git(destination, 'bundle', 'verify', str(bundle))
            advertised = _git(destination, 'bundle', 'list-heads', str(bundle)).splitlines()
            if not 0 < len(advertised) <= 4096:
                raise SourceCarrierError('invalid bundle reference count')
            refspecs = []
            for i, line in enumerate(advertised):
                oid, name = line.decode().split(' ', 1)
                if not _hex(oid, 40) or (name != 'HEAD' and not name.startswith('refs/')):
                    raise SourceCarrierError('invalid bundle reference')
                refspecs.append(name + ':refs/carrier/source-' + str(i))
            _git(destination, 'fetch', '--quiet', '--no-tags', str(bundle), *refspecs)
        # A 40-hex object name is not necessarily a commit: annotated tags peel.
        # Bind raw object types before any checkout, then bind the resulting HEAD.
        if _git(destination, 'cat-file', '-t', node['commit']).strip() != b'commit':
            raise SourceCarrierError('declared source object is not a raw commit')
        if _git(destination, 'cat-file', '-t', node['tree']).strip() != b'tree':
            raise SourceCarrierError('declared source tree is not a raw tree')
        if _git(destination, 'rev-parse', node['commit'] + '^{tree}').decode().strip() != node['tree']:
            raise SourceCarrierError('source tree mismatch')
        for ref, binding in node.get('refs', {}).items():
            _git(destination, 'check-ref-format', ref)
            if _git(destination, 'cat-file', '-t', binding['object']).decode().strip() != binding['type']:
                raise SourceCarrierError('named ref raw object type mismatch')
            if binding['type'] == 'commit':
                if binding['object'] != node['commit']:
                    raise SourceCarrierError('named ref points at a different commit')
            else:
                header = _git(destination, 'cat-file', 'tag', binding['object']).split(b'\n\n', 1)[0].splitlines()
                expected = [b'object ' + node['commit'].encode(), b'type commit',
                            b'tag ' + ref.removeprefix('refs/tags/').encode()]
                if header[:3] != expected or _git(destination, 'rev-parse', binding['object'] + '^{commit}').decode().strip() != node['commit']:
                    raise SourceCarrierError('annotated tag name or target mismatch')
            _git(destination, 'update-ref', ref, binding['object'])
        entries = {}
        for line in _git(destination, 'ls-tree', '-rz', node['commit']).split(b'\0'):
            if not line:
                continue
            meta, name = line.split(b'\t', 1)
            mode, kind, oid = meta.decode().split()
            path = name.decode('utf-8'); _relative(path)
            entries[path] = (mode, kind, oid)
            # Reject escaping symlinks before checkout; no special file extraction.
            if mode == '120000':
                target = _git(destination, 'cat-file', 'blob', oid).decode('utf-8')
                resolved = os.path.normpath(str(Path(path).parent / target))
                if target.startswith('/') or resolved == '..' or resolved.startswith('../') or '.git' in Path(resolved).parts:
                    raise SourceCarrierError('escaping source symlink')
        links = {path: entry[2] for path, entry in entries.items() if entry[0] == '160000'}
        if links != {path: child['commit'] for path, child in node['gitlinks'].items()}:
            raise SourceCarrierError('declared gitlinks differ from source tree')
        _git(destination, 'checkout', '--quiet', '--detach', node['commit'])
        _git(destination, 'remote', 'add', 'origin', node['repository'])
        actual = {}
        if '.gitmodules' in entries:
            # Git returns 1 for a valid config with no matching keys. Upstream
            # repositories may retain an empty .gitmodules after removing their
            # last dependency; malformed configs must still fail closed.
            for line in _git(destination, 'config', '-z', '--file', '.gitmodules', '--get-regexp', r'^submodule\..*\.path$', ok=(0, 1)).split(b'\0'):
                if not line:
                    continue
                config, path = line.decode().split('\n', 1)
                url = _git(destination, 'config', '--file', '.gitmodules', '--get', config[:-5] + '.url').decode().strip()
                if url.startswith('.'):
                    url = urljoin(node['repository'].rstrip('/') + '/', url)
                actual[path] = _repository(url)
        if actual != {p: _repository(c['repository']) for p, c in node['gitlinks'].items()}:
            raise SourceCarrierError('gitmodules repository mapping mismatch')
        for path, child in node['gitlinks'].items():
            dest = destination / path
            # Git may create the empty gitlink directory on checkout.
            if dest.exists():
                dest.rmdir()
            self._populate((_repository(child['repository']), child['commit']), dest)
        if links:
            _git(destination, 'submodule', 'init')
        if _git(destination, 'rev-parse', '--verify', 'HEAD').decode().strip() != node['commit']:
            raise SourceCarrierError('checked out HEAD differs from declared commit')
        self._verify(destination, entries)
        _git(destination, 'fsck', '--full', '--no-dangling')

    @staticmethod
    def _verify(destination, entries):
        # Read actual tracked bytes, independent of index stat caches/filters.
        for path, (mode, kind, oid) in entries.items():
            if mode == '160000':
                continue
            q = destination / path
            if mode == '120000':
                if not q.is_symlink():
                    raise SourceCarrierError('source symlink mode mismatch')
                raw = os.readlink(q).encode()
            elif mode in ('100644', '100755'):
                if q.is_symlink() or not q.is_file() or bool(q.stat().st_mode & 0o111) != (mode == '100755'):
                    raise SourceCarrierError('source file mode mismatch')
                raw = q.read_bytes()
            else:
                raise SourceCarrierError('unsupported source mode')
            digest = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            if digest != oid:
                raise SourceCarrierError('source tracked byte mismatch')
        if _git(destination, 'status', '--porcelain', '--untracked-files=all'):
            raise SourceCarrierError('source checkout is dirty')
        if _git(destination, 'rev-parse', '--is-shallow-repository').strip() != b'false' or (destination / '.git/objects/info/alternates').exists():
            raise SourceCarrierError('source is not independent full history')

    def materialize(self, repository, ref, destination):
        destination = Path(destination).absolute()
        if os.path.lexists(destination):
            raise SourceCarrierError('source destination must be absent')
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.source-carrier-', dir=destination.parent) as tmp:
            stage = Path(tmp) / 'source'
            self._populate((_repository(repository), ref), stage)
            _git(stage, 'remote', 'set-url', 'origin', repository)
            # No overwrite: caller owns live selection/rollback.
            if os.path.lexists(destination):
                raise SourceCarrierError('source destination appeared during staging')
            os.rename(stage, destination)

    def prepare_git(self, destination):
        """Prepare verified repositories and a process-scoped Git config for OS callers."""
        destination = Path(destination).absolute()
        if os.path.lexists(destination):
            raise SourceCarrierError('Git transport destination must be absent')
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.source-git-', dir=destination.parent) as tmp:
            stage = Path(tmp) / 'pool'; stage.mkdir()
            config = stage / 'gitconfig'
            repositories = {}
            for i, (key, node) in enumerate(self.nodes.items()):
                checkout = Path(tmp) / ('checkout-' + str(i))
                self._populate(key, checkout)
                relative = 'repositories/' + hashlib.sha256(key[0].encode()).hexdigest() + '.git'
                bare = stage / relative
                if not bare.exists():
                    bare.mkdir(parents=True); _git(bare, 'init', '--bare', '--quiet')
                branch = 'refs/heads/offline/' + node['commit']
                _git(bare, 'fetch', '--quiet', '--no-tags', str(checkout / '.git'), node['commit'] + ':' + branch)
                for ref, binding in node.get('refs', {}).items():
                    _git(bare, 'fetch', '--quiet', '--no-tags', str(checkout / '.git'), ref + ':' + ref)
                    if _git(bare, 'rev-parse', '--verify', ref).decode().strip() != binding['object']:
                        raise SourceCarrierError('named ref transfer changed its object')
                if key[0] not in repositories:
                    _git(bare, 'symbolic-ref', 'HEAD', branch)
                    repositories[key[0]] = relative
                shutil.rmtree(checkout)
            for repository, relative in repositories.items():
                url = (destination / relative).as_uri()
                # Provisioning creates a root-owned read-only pool for target-user Git.
                _git(stage, 'config', '--file', str(config), '--add', 'safe.directory', str(destination / relative))
                for canonical in (repository, repository + '.git'):
                    _git(stage, 'config', '--file', str(config), '--add', 'url.' + url + '.insteadOf', canonical)
            _git(stage, 'config', '--file', str(config), 'protocol.file.allow', 'always')
            _git(stage, 'config', '--file', str(config), 'core.hooksPath', os.devnull)
            if os.path.lexists(destination):
                raise SourceCarrierError('Git transport destination appeared')
            os.rename(stage, destination)
        return str(destination / 'gitconfig')

    def verify(self):
        with tempfile.TemporaryDirectory(prefix='source-carrier-verify-') as tmp:
            for i, key in enumerate(self.nodes):
                self._populate(key, Path(tmp) / str(i))


def configured_carrier(manifest_path=None, manifest_sha256=None, *, env=None):
    env = os.environ if env is None else env
    if manifest_path is None and manifest_sha256 is None:
        manifest_path = env.get('KILIX_SOURCE_CARRIER_MANIFEST')
        manifest_sha256 = env.get('KILIX_SOURCE_CARRIER_SHA256')
        if manifest_path is None and manifest_sha256 is None:
            if not os.path.lexists(DEFAULT):
                return None
            manifest_path = str(DEFAULT)
            manifest_sha256 = _read(DEFAULT.parent, 'manifest.sha256', 128).decode().strip()
    if not manifest_path or not manifest_sha256:
        raise SourceCarrierError('both source carrier path and digest are required')
    return Carrier(manifest_path, manifest_sha256)


def materialize_source(repository, ref, destination, *, manifest_path=None, manifest_sha256=None, env=None):
    try:
        carrier = configured_carrier(manifest_path, manifest_sha256, env=env)
        if carrier is None:
            return False
        carrier.materialize(repository, ref, destination)
        return True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        raise SourceCarrierError('invalid or unreadable source carrier: ' + str(exc)) from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('verify', 'materialize', 'prepare-git'))
    parser.add_argument('--manifest'); parser.add_argument('--sha256')
    parser.add_argument('--repository'); parser.add_argument('--ref'); parser.add_argument('--destination')
    args = parser.parse_args()
    try:
        carrier = configured_carrier(args.manifest, args.sha256)
        if carrier is None:
            return 3
        if args.action == 'verify':
            carrier.verify()
        elif args.action == 'prepare-git':
            print(carrier.prepare_git(args.destination))
        else:
            carrier.materialize(args.repository, args.ref, args.destination)
        return 0
    except (SourceCarrierError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        parser.exit(1, 'source carrier refused: ' + str(exc) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
