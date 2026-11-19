"""Rootful CF1800 bootstrap: native paths, signed payloads, bound installation.

Preparation uses pinned downloads only. Device deployment belongs exclusively to
InstallationSession after genuine Data initialization; no fakefs or /var/jb.
"""
from copy import copy, deepcopy
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import plistlib
import posixpath
import re
import shlex
import shutil
import struct
import subprocess
import tarfile
from types import SimpleNamespace

from core.patch import select
from .. import rootful_runtime
from ..rootless_bootstrap import artifacts as a, macho, sileo
from ..rootless_bootstrap.dependencies import audit, paragraphs

HERE = Path(__file__).resolve().parent
PATCH_ID = 'rootfs.rootful_bootstrap'
LABEL = 'com.n56.ios15.rootful-bootstrap'
DAEMON = '/System/Library/LaunchDaemons/' + LABEL + '.plist'
BASE = '/.n56-bootstrap/rootful'
LAYOUT = 'system-rootful-v1'


def output(ctx):
    """ctx.wk('rootful-final'): signed at build, deployed unchanged by install in the same workdir."""
    return Path(ctx.wk('rootful-final')).resolve()


def _ctx(ctx):
    from core.jailbreak_mode import selected_mode
    if (ctx.t.get('version'), ctx.t.get('build'), selected_mode(ctx.t)) != ('ios15', '19H422', 'rootful'):
        raise ValueError('rootful bootstrap requires iOS15 19H422 rootful layout')
    if 'rootless' in ctx.t.get('features', ()):
        raise ValueError('rootful cannot select a /var/jb bootstrap simultaneously')


def fingerprint():
    paths = [p for p in HERE.rglob('*') if p.is_file() and p.suffix in ('.py', '.sh', '.json')]
    paths += [Path(rootful_runtime.__file__), Path(a.__file__), Path(macho.__file__), Path(sileo.__file__), HERE.parent/'rootless_bootstrap/dependencies.py', a.REPO/'tools/rootless-runtime/random-secret.c',
              a.REPO/'tools/rootless-runtime/legacy-libSystem-ios12.tbd']
    return hashlib.sha256(b''.join(str(p.relative_to(a.REPO)).encode()+p.read_bytes()
                                  for p in sorted(paths) if '__pycache__' not in p.parts)).hexdigest()


def job():
    return dict(Label=LABEL, ProgramArguments=[BASE+'/bootstrap-sh', BASE+'/bootstrap-stage0.sh'],
                UserName='root', RunAtLoad=True, KeepAlive={'SuccessfulExit': False},
                ThrottleInterval=15, ProcessType='Background',
                EnvironmentVariables=dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin', HOME='/var/root', TMPDIR='/var/tmp'),
                StandardOutPath='/var/log/n56-rootful-bootstrap.log', StandardErrorPath='/var/log/n56-rootful-bootstrap.log')


def relative(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name or any(ord(c)<32 for c in name):
        raise ValueError('unsafe rootful archive path: '+name)
    normalized = path.as_posix()
    if normalized == '.': return None
    if path.parts[:2] == ('var', 'jb') or path.parts[:3] == ('private', 'var', 'jb'):
        raise ValueError('rootless payload supplied to rootful')
    if path.parts[0] in ('etc', 'var'):
        path = PurePosixPath('private') / path
        normalized = path.as_posix()
    if path.parts[0] not in ('usr','bin','sbin','binpack','Library','Applications','private','lib',
                             '.n56-bootstrap','.procursus_strapped','prep_bootstrap.sh','boot','mnt'):
        raise ValueError('unexpected rootful archive namespace: '+name)
    if path.parts[:2] == ('usr','lib') and path.name.startswith(('libSystem.','libobjc.')):
        raise ValueError('rootful must preserve native J96 libSystem/libobjc')
    return normalized


def storage(path):
    """The runtime /private/var subtree is physically selected Data15."""
    if path == 'private/var': return 'data', None
    if path.startswith('private/var/'): return 'data', path[len('private/var/'):]
    return 'system', path


def _dependencies(records, index, inventory_path, inventory):
    """inventory comes from artifacts.native_inventory(ctx): the mounted J96 dyld cache."""
    if inventory.get('build') != '19H422': raise ValueError('wrong J96 dyld inventory')
    native=set(inventory['images']); unresolved=[]
    def exists(path):
        path=posixpath.normpath(path).lstrip('/');seen=set()
        while path not in seen:
            seen.add(path); row=index.get(path)
            if not row:return '/'+path in native
            if row['type']=='0':return True
            if row['type']=='2':
                target=row['link'];path=posixpath.normpath(target if target.startswith('/') else posixpath.join(posixpath.dirname(path),target)).lstrip('/')
            else:return False
        return False
    for row in records:
        for imported in row['imports']:
            loader=posixpath.dirname(row['runtime_path']);paths=[]
            if imported.startswith('@loader_path/'):
                paths=[posixpath.normpath(loader+imported[len('@loader_path'):])]
            elif imported.startswith('@rpath/'):
                paths=[posixpath.normpath(p.replace('@loader_path',loader)+imported[len('@rpath'):]) for p in row['rpaths']]
            elif imported.startswith('/'):paths=[imported]
            if not any(exists(p) for p in paths):unresolved.append(dict(image=row['runtime_path'],imported=imported,candidates=paths))
    return dict(unresolved=unresolved,native_inventory_sha256=a.sha(inventory_path),layout='native-rootful-paths')


def _build(ctx):
    out=output(ctx);out.mkdir(parents=True,exist_ok=True)
    downloads=a.DOWNLOADS;downloads.mkdir(parents=True,exist_ok=True)
    spec=json.loads((HERE/'sources.json').read_text())
    for name,row in spec['artifacts'].items():
        path=downloads/name
        pass
        if not path.is_file() or a.sha(path)!=row['sha256']:raise ValueError('missing/pin-changed rootful download: '+name)
    zstd=a._zstd()
    # Binpack remains the pinned, ordinary-arm64 upstream tool supply.
    binpack=downloads/'binpack.dmg'
    pass
    tools=a.tools(out)
    runtime=rootful_runtime.prepare(SimpleNamespace(t=ctx.t,patch_reports=ctx.patch_reports,
                                                   wk=lambda name:str(out/'runtime-helper')))
    helper_path=Path(runtime['path']);_,helper_facts=macho.inspect(helper_path.read_bytes())
    derived,seal=sileo.prepare(out,spec['artifacts']['sileo.deb'],zstd,app_prefix='Applications/Sileo.app')
    from . import ssh
    ssh_files,ssh_report=ssh.material(out,getattr(ctx,'rootful_ssh_public_key',None))
    index={};records=[];cases={};status='';controls=[];prep=None
    archives={kind:tarfile.open(out/(kind+'.tar'),mode='w',format=tarfile.PAX_FORMAT) for kind in ('system','data')}
    try:
        def emit(member,raw,origin):
            nonlocal status,prep
            path=relative(member.name)
            if path is None:return
            # Upstream strap marker is committed only after actual dpkg/apt success.
            if path in ('.procursus_strapped','boot','mnt'):return
            if path=='prep_bootstrap.sh':
                prep=raw;path=BASE.lstrip('/')+'/prep_bootstrap.sh'
            if member.islnk():raise ValueError('rootful hardlink requires explicit safe conversion')
            if not (member.isfile() or member.isdir() or member.issym()):raise ValueError('rootful special node rejected')
            if path in index:
                if member.isdir() and index[path]['type']=='5':return
                raise ValueError('duplicate rootful payload: '+path)
            if path.casefold() in cases and cases[path.casefold()]!=path:raise ValueError('rootful casefold collision')
            cases[path.casefold()]=path
            if any(index.get(str(p),{}).get('type')=='2' for p in PurePosixPath(path).parents if str(p)!='.'):
                raise ValueError('rootful archive writes through a payload symlink')
            if member.issym():
                link=member.linkname
                if not link or '\\' in link or any(ord(c)<32 for c in link):raise ValueError('unsafe rootful symlink')
                target=posixpath.normpath(link if link.startswith('/') else posixpath.join(posixpath.dirname(path),link))
                if target.startswith('../') or target in ('..','.'):raise ValueError('rootful symlink escapes root')
                if any(existing.startswith(path+'/') for existing in index):raise ValueError('late symlink replaces a populated parent')
            row=dict(path=path,type=member.type.decode(),mode=member.mode,uid=member.uid,gid=member.gid,origin=origin)
            if member.issym():row['link']=member.linkname
            if raw is not None:
                if raw[:4] in macho.MAGICS:
                    raw,facts=macho.inspect(raw)
                    file=(out/'signing'/path if path.startswith('Applications/') else out/'signing'/(hashlib.sha256(path.encode()).hexdigest()+'.macho'));file.parent.mkdir(parents=True,exist_ok=True)
                    file.write_bytes(raw);file.chmod(member.mode & 0o7777)
                    records.append(dict(path=str(file.resolve()),runtime_path='/'+path,sha256=a.sha(file),origin=origin,**facts))
                if path.startswith('Applications/') and '.app/' in path:
                    resource=out/'signing'/path;resource.parent.mkdir(parents=True,exist_ok=True)
                    resource.write_bytes(raw);resource.chmod(member.mode & 0o7777)
                row.update(size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
                if path=='Library/dpkg/status':status=raw.decode()
            kind,rel=storage(path)
            if rel is None:return
            item=copy(member);item.name=rel;item.pax_headers={};item.mtime=0
            if raw is not None:item.size=len(raw)
            archives[kind].addfile(item,io.BytesIO(raw) if raw is not None else None)
            index[path]=row
        with (downloads/'bootstrap-1800.tar.zst').open('rb') as f,zstd.ZstdDecompressor().stream_reader(f) as stream,tarfile.open(fileobj=stream,mode='r|') as tar:
            for member in tar:emit(member,tar.extractfile(member).read() if member.isfile() else None,'official-rootful-bootstrap')
        for path,origin in ((derived,'sileo-resealed'),(downloads/'dhinakg-keyring_2023.04.02_all.deb','keyring'),
                            (downloads/'libkrw0-tfp0_1.1.1_iphoneos-arm.deb','official-rootful-tfp0-plugin')):
            members=a.ar_members(path)
            with a._archive(next(v for k,v in members.items() if k.startswith('control.tar')),zstd) as tar:
                for m in tar:
                    if PurePosixPath(m.name).name=='control':controls.append(dict(paragraphs(tar.extractfile(m).read().decode())[0], Status='plan only not-installed'))
            with a._archive(next(v for k,v in members.items() if k.startswith('data.tar')),zstd) as tar:
                for m in tar:emit(m,tar.extractfile(m).read() if m.isfile() else None,origin)
            raw=path.read_bytes();m=tarfile.TarInfo(BASE.lstrip('/')+'/offline-debs/'+path.name);m.mode=0o600;m.size=len(raw)
            emit(m,raw,origin+'-archive')
        # Place original binpack tools on native rootful paths; no LC path rewrites.
        for row in tools:
            source=Path(row['path']);name=str(source.relative_to(out/'support'))
            path='usr/bin/uicache' if name=='usr/bin/uicache' else 'usr/libexec/n56-binpack/'+name
            if path in index: continue  # Prefer the valid original rootful tool already in the bootstrap.
            m=tarfile.TarInfo(path);m.mode=0o755;emit(m,source.read_bytes(),'pinned-binpack')
        for notice in sorted((out/'licenses/binpack').rglob('*')):
            if notice.is_file():
                m=tarfile.TarInfo(BASE.lstrip('/')+'/licenses/binpack/'+str(notice.relative_to(out/'licenses/binpack')))
                m.mode=0o644;emit(m,notice.read_bytes(),'binpack-copyright-notice')
        shell=next(Path(row['path']) for row in tools if row['path'].endswith('/usr/bin/mksh'))
        for path,raw,mode in [('usr/libexec/n56-rootful-runtime',helper_path.read_bytes(),0o755),
                              (BASE.lstrip('/')+'/bootstrap-sh',shell.read_bytes(),0o755),
                              *[(BASE.lstrip('/')+'/'+name,(HERE/'scripts'/name).read_bytes(),0o755) for name in ('bootstrap-stage0.sh','firstboot.sh')]]:
            m=tarfile.TarInfo(path);m.mode=mode;emit(m,raw,'n56-rootful-runtime')
        repositories=b'Types: deb\nURIs: https://repo.palera.in\nSuites: ./\n\nTypes: deb\nURIs: https://ellekit.space\nSuites: ./\n'
        m=tarfile.TarInfo('private/etc/apt/sources.list.d/n56-rootful.sources');m.mode=0o644
        emit(m,repositories,'official-loader-rootful-repositories')
        for path,(raw,mode) in ssh_files.items():
            m=tarfile.TarInfo(path);m.mode=mode;emit(m,raw,'ios14-equivalent-ssh')
        for path,target in {'binpack/usr/bin/dropbearkey':'dropbearmulti','binpack/usr/sbin/dropbear':'../bin/dropbearmulti'}.items():
            m=tarfile.TarInfo(path);m.type=tarfile.SYMTYPE;m.linkname=target;m.mode=0o777
            emit(m,None,'ios14-equivalent-ssh-link')
        if not prep or not status:raise ValueError('rootful bootstrap lacks real prep/status')
        for control in controls:
            if control['Architecture'] not in ('iphoneos-arm','all'):raise ValueError('rootless Debian ABI in rootful package')
        # Modern native J96 firmware dependencies are generated by real firmware at first boot.
        extra='\n\n'.join('\n'.join(k+': '+v for k,v in r.items()) for r in controls)
        dependencies=audit(status+'\n\n'+extra,architecture='iphoneos-arm')
        missing=[r for r in dependencies['unresolved'] if not all(alt.strip().split()[0].split('(')[0] in ('firmware','cy+cpu.arm64','cy+kernel.darwin') for alt in r['dependency'].split('|'))]
        # Sileo's firmware>=12.2 | libswift alternative is satisfied by native15 firmware.
        missing=[r for r in missing if not re.search(r'(^|\|)\s*firmware(?:\s|\()',r['dependency'])]
        dependencies['non_firmware_unresolved']=missing
        dyld=_dependencies(records,index,*a.native_inventory(ctx))
        if missing or dyld['unresolved']:raise ValueError('rootful dependency closure incomplete: '+str((missing,dyld['unresolved'])[:2]))
    finally:
        for tar in archives.values():tar.close()
    package_identity=hashlib.sha256(json.dumps(index,sort_keys=True).encode()).hexdigest()
    report=dict(schema=1,patch=PATCH_ID,output=str(out),source_fingerprint=fingerprint(),layout=LAYOUT,
                jailbreak_mode='rootful',package_identity=package_identity,fingerprint=package_identity,
                signing_records=records,runtime_helper=runtime,daemons={DAEMON:job()},dependencies=dependencies,
                dyld=dyld,sileo=seal,ssh=ssh_report,payload_index=index,prepared=True,ready=False,runtime_validated=False,
                basic_firstboot_implemented=True,basic_paleinfo_required=False,basic_kernel_rw_required=False,
                amfi_policy='palera1n-trustcache-bypass',root_remount_implemented=True,
                physical_storage=dict(system='/usr,/Library,/Applications',data='/private/var'),
                device_access=False,bootstrap_installed=False,
                kernel_rw_plugin='upstream libkrw0-tfp0; actual task-port availability evaluated at runtime',files=[])
    a.write_json(out/'payload-index.json',index)
    tracked=[out/'system.tar',out/'data.tar',out/'payload-index.json',helper_path]+[Path(r['path']) for r in records]
    tracked += [p for p in (out/'signing/Applications').rglob('*') if p.is_file()]
    report['files']=[dict(path=str(p.resolve()),sha256=a.sha(p)) for p in sorted(set(tracked))]
    a.write_json(out/'package.json',report)
    return report


def validate(package,ctx):
    _ctx(ctx)
    if package.get('source_fingerprint')!=fingerprint() or package.get('output')!=str(output(ctx)):
        raise ValueError('rootful source/cache selection changed; rebuild offline')
    if package.get('layout')!=LAYOUT or package.get('jailbreak_mode')!='rootful':raise ValueError('rootful layout mismatch')
    from ..signed_artifacts import validate_helper
    validate_helper(package['runtime_helper'],package['runtime_helper']['sources'])
    for row in package['files']:
        path=Path(row['path'])
        if output(ctx) not in path.resolve().parents or path.is_symlink() or not path.is_file() or a.sha(path)!=row['sha256']:
            raise ValueError('rootful package file changed: '+str(path))
    for row in package['signing_records']:
        if a.sha(row['path'])!=row['sha256']:raise ValueError('rootful signing input changed')
    return package


def prepare(ctx):
    _ctx(ctx);manifest=output(ctx)/'package.json'
    if manifest.is_file():package=validate(json.loads(manifest.read_text()),ctx)
    elif getattr(ctx,'completed_package',False):raise ValueError('completed rootful package missing; no re-signing during installation')
    else:package=_build(ctx)
    ctx.patch_reports[PATCH_ID]=package
    return package


def signing_inputs(ctx):
    return dict(paths=[r['path'] for r in prepare(ctx)['signing_records']],detached=[],cache_plans=[])


def launchd_transform(ctx,current):
    package=prepare(ctx);result=deepcopy(current);jobs=result.get('LaunchDaemons')
    if not isinstance(jobs,dict):raise ValueError('rootful requires the single launchd composer')
    if DAEMON in jobs and jobs[DAEMON]!=package['daemons'][DAEMON]:raise ValueError('rootful launchd owner conflict')
    if any(isinstance(v,dict) and v.get('Label')==LABEL and k!=DAEMON for k,v in jobs.items()):raise ValueError('rootful launchd label conflict')
    jobs[DAEMON]=deepcopy(package['daemons'][DAEMON]);return result


def _registered(ctx,package):
    from core.trustcache import TrustCache
    tc=ctx.patch_reports.get('rootfs.trustcache',{});path=Path(tc.get('output') or '')
    if not path.is_file() or a.sha(path)!=tc.get('output_sha256'):raise ValueError('rootful combined TC changed/missing')
    version,entries=TrustCache._entries(path.read_bytes())
    typed={digest.hex():entry[20] for digest,entry in entries.items()}
    signed={row['cdhash']:row['hash_type'] for row in tc.get('signed_files',[])}
    for row in package['signing_records']:
        if typed.get(row['cdhash'])!=row['hash_type'] or signed.get(row['cdhash'])!=row['hash_type']:
            raise ValueError('rootful Mach-O missing from actual combined TC: '+row['runtime_path'])
    launch=ctx.patch_reports.get('rootfs.launchd_cache',{})
    if launch.get('composer')!='patches.ios15.impl.rootfs.launchd_cache' or 'rootful_bootstrap' not in launch.get('transforms',[]):raise ValueError('rootful composer missing')
    plist,sig=Path(launch.get('plist') or ''),Path(launch.get('sig') or '')
    if not plist.is_file() or not sig.is_file() or a.sha(plist)!=launch.get('plist_sha256') or a.sha(sig)!=launch.get('sig_sha256'):raise ValueError('rootful launchd signature pair changed')
    expected=job()
    if 'rootfs.paleinfo_runtime' in {p.id for p in select(ctx.t)['rootfs']}:
        from ..paleinfo_runtime import wrapped_job
        expected=wrapped_job(expected)
    if plistlib.loads(plist.read_bytes()).get('LaunchDaemons',{}).get(DAEMON)!=expected:raise ValueError('rootful final launchd job differs')
    subprocess.run(['codesign','--verify','--strict','--detached',str(sig),str(plist)],check=True,capture_output=True)
    cdhash=TrustCache._cdhash(str(plist),str(sig)).hex()
    if typed.get(cdhash)!=2 or signed.get(cdhash)!=2:raise ValueError('rootful composed launchd not in actual TC')
    kpf=ctx.patch_reports.get('kc.palera1n',{})
    if kpf.get('jailbreak_layout')!='rootful' or kpf.get('root_remount_rw_patch') is not True or not kpf.get('root_remount_rw_evidence'):
        raise ValueError('rootful requires real APFS RW KPF evidence')
    return tc


def validate_binding(value):
    import uuid
    if not isinstance(value,dict) or value.get('layout')!=LAYOUT or value.get('build')!='19H422' or value.get('runtime_root')!='/':raise ValueError('rootful actual install binding required')
    if any(isinstance(value.get(k),bool) or not isinstance(value.get(k),int) or not 4<=value[k]<=100 for k in ('system_slice','data_slice')) or value['system_slice']==value['data_slice']:raise ValueError('unsafe rootful volume slices')
    identities=[uuid.UUID(value[k]) for k in ('system_uuid','data_uuid')]
    if identities[0]==identities[1] or any(v.int==0 for v in identities):raise ValueError('unsafe rootful volume UUIDs')
    return deepcopy(value)


def deploy(ctx,package):
    validate(package,ctx);_registered(ctx,package)
    identity=validate_binding(getattr(ctx,'rootful_binding',None));identity.update(package_fingerprint=package['fingerprint'],amfi_policy=package['amfi_policy'])
    if getattr(ctx,'installation',None) is None:raise ValueError('rootful deploy requires authorized InstallationSession')
    from core.apfs import Apfs
    from ..system_policy import inspect_volume
    volumes={v[0]:v[2] for v in Apfs(ctx).volumes()}
    import uuid
    for name in ('system','data'):
        facts=inspect_volume(volumes[identity[name+'_slice']],identity[name+'_slice'],require_live_system=name=='system')
        if str(uuid.UUID(hex=facts['uuid'])).upper()!=identity[name+'_uuid']:raise ValueError('rootful selected UUID changed')
    ctx.installation.mount_system();ctx.installation.mount_data();session=ctx.ssh
    from ..rootless_bootstrap.binding import check_mounts
    check_mounts(session.sh('/sbin/mount').decode(),identity)
    version=plistlib.loads(session.sh('cat /mnt6/System/Library/CoreServices/SystemVersion.plist'))
    if version.get('ProductBuildVersion')!='19H422':raise ValueError('foreign rootful System at /mnt6')
    session.sh('test -f /mnt7/.n56-ios15-data && test ! -L /mnt7/.n56-ios15-data && test ! -e /mnt7/jb && test ! -L /mnt7/jb')
    q=shlex.quote;pending='/mnt6/.n56-rootful-install.pending'
    session.sh('test ! -e '+pending+' && test ! -L '+pending+
               ' && test ! -e '+pending+'.staged && test ! -L '+pending+'.staged && mkdir -m 700 '+pending)
    # Check EVERY existing destination parent before any overlay write. /private/var
    # is split to /mnt7; there are no native12 or physical Preboot destinations.
    parents=set();leaves=[]
    for path,row in package['payload_index'].items():
        kind,rel=storage(path)
        if rel is None:continue
        remote=('/mnt7/' if kind=='data' else '/mnt6/')+rel
        parents.update(str(p) for p in PurePosixPath(remote).parents if str(p) not in ('.','/'))
        if row['type'] in ('0','5'):leaves.append(remote)
    guard='set -eu\n'+''.join('test ! -L '+q(p)+'\n' for p in sorted(parents))+''.join('test ! -L '+q(p)+'\n' for p in leaves)
    file=output(ctx)/'deployment-guard.sh';file.write_text(guard);session.put(str(file),pending+'/guard.sh')
    session.sh('/bin/sh '+pending+'/guard.sh')
    for kind in ('system','data'):
        local=output(ctx)/(kind+'.tar');remote=pending+'/'+kind+'.tar';session.put(str(local),remote)
        if hashlib.sha256(session.sh('cat '+q(remote))).hexdigest()!=a.sha(local):raise ValueError('rootful archive transfer changed')
    # Retain pending transaction on any failure; no destructive cleanup/retry.
    for kind,point in (('system','/mnt6'),('data','/mnt7')):session.sh('tar -xpf '+pending+'/'+kind+'.tar -C '+point)
    for path,row in package['payload_index'].items():
        if row['type']!='0':continue
        kind,rel=storage(path);remote=('/mnt7/' if kind=='data' else '/mnt6/')+rel
        if hashlib.sha256(session.sh('cat '+q(remote))).hexdigest()!=row['sha256']:raise ValueError('rootful installed file differs: '+path)
    for name,raw in [('binding.json',json.dumps(identity,indent=2)+'\n'),('package.identity',package['package_identity']+'\n')]:
        local=output(ctx)/name;local.write_text(raw);local.chmod(0o600)
        dest='/mnt6'+BASE+'/'+name;session.put(str(local),dest);session.sh('chown 0:0 '+q(dest)+' && chmod 600 '+q(dest))
    session.sh('mv '+pending+' '+pending+'.staged');session.sync()
    report=dict(staged=True,installed=True,ready=False,runtime_validated=False,binding=identity,
                package_identity=package['package_identity'],device_firstboot_validated=False)
    a.write_json(output(ctx)/'deployment.json',report);ctx.patch_reports[PATCH_ID+'.deployment']=report
    return report
