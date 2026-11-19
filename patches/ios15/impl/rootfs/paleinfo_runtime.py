"""Signed ordinary-arm64 paleinfo consumer; rootless startup stays independent."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
from core.context import REPO
from core.trustcache import TrustCache
from .rootless_runtime import _inspect

ROOT=Path(REPO)
TOOLS=ROOT/'tools/rootless-runtime'
DEVICE_PATH='/usr/libexec/n56-paleinfo'
RUNTIME_SOURCE='AMFI-policy-call-0x1000'


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prepare(ctx):
    from core.jailbreak_mode import selected_mode
    mode = selected_mode(ctx.t) or 'rootless'
    flags = 0x81 if mode == 'rootful' else 0x82
    if getattr(ctx, 'completed_package', False):
        from .signed_artifacts import validate_helper
        package = ctx.patch_reports['rootfs.paleinfo_runtime']
        if package.get('jailbreak_mode', 'rootless') != mode or package.get('flags', 0x82) != flags:
            raise ValueError('signed paleinfo consumer layout differs from selected kernel policy')
        validate_helper(package['helper'], package['sources'])
        return package
    root=Path(ctx.wk('paleinfo-userland'));root.mkdir(parents=True,exist_ok=True)
    output=root/'n56-paleinfo';manifest=root/'package.json'
    files=[Path(__file__),TOOLS/'paleinfo.c',TOOLS/'paleinfo-libSystem-ios12.tbd',
           TOOLS/'runtime.entitlements',ROOT/'tools/palera1n-kpf/include/paleinfo-user.h',
           ROOT/'tools/palera1n-kpf/vendor/include/paleinfo.h']
    sources={str(path.relative_to(ROOT)):sha(path) for path in files}
    if output.is_file() and manifest.is_file():
        package=json.loads(manifest.read_text())
        if package.get('jailbreak_mode', 'rootless')==mode and package.get('sources')==sources and package.get('helper',{}).get('sha256')==sha(output):
            subprocess.run(['codesign','--verify','--strict',str(output)],check=True,capture_output=True)
            ctx.patch_reports['rootfs.paleinfo_runtime']=package
            return package
    sdk=subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip()
    obj=root/'paleinfo.arm64.o'
    subprocess.run(['xcrun','--sdk','macosx','clang','-target','arm64-apple-ios12.0','-isysroot',sdk,
        '-Wno-incompatible-sysroot','-Wno-deprecated-declarations','-march=armv8-a','-mno-outline-atomics',
        f'-DN56_PALEINFO_FLAGS={flags}', '-O2','-Wall','-Wextra','-Werror','-c',str(TOOLS/'paleinfo.c'),'-o',str(obj)],check=True)
    subprocess.run(['xcrun','--sdk','macosx','clang','-target','arm64-apple-ios12.0','-nostdlib',
        '-Wno-incompatible-sysroot',str(obj),str(TOOLS/'paleinfo-libSystem-ios12.tbd'),
        '-Wl,-e,_main','-Wl,-platform_version,ios,12.0,12.0','-o',str(output)],check=True)
    helper=_inspect(output)
    subprocess.run(['codesign','-s','-','-f','--timestamp=none','--identifier','com.n56.ios15.paleinfo',
        '--entitlements',str(TOOLS/'runtime.entitlements'),str(output)],check=True,capture_output=True)
    subprocess.run(['codesign','--verify','--strict',str(output)],check=True,capture_output=True)
    output.chmod(0o755)
    cdhash,kind=TrustCache._cdhash_any(str(output))
    helper.update(path=str(output.resolve()),device_path=DEVICE_PATH,sha256=sha(output),
        cdhash=cdhash.hex(),hash_type=kind,signed=True,kernel_rw_supplied=False)
    package=dict(patch='rootfs.paleinfo_runtime',jailbreak_mode=mode,flags=flags,prepared=True,helper=helper,sources=sources,
        runtime_source=RUNTIME_SOURCE,metadata_path='/private/var/run/n56-paleinfo',
        fd_format='LE offset=4 followed by upstream packed paleinfo v2; ephemeral regular file, NOT /dev/rdisk0',
        launchd_owner='patches.ios15.impl.rootfs.launchd_cache',kernel_rw_provided=False,
        specialized_dev_rdisk0_clients_supported=False,paleinfo_fd_transport_implemented=True,
        runtime_validated=False,ready=False,device_access=False)
    manifest.write_text(json.dumps(package,indent=2)+'\n')
    ctx.patch_reports['rootfs.paleinfo_runtime']=package
    return package


def wrapped_job(original):
    result=deepcopy(original)
    arguments=result.get('ProgramArguments')
    if not isinstance(arguments,list) or not arguments or not isinstance(arguments[0],str) or not arguments[0].startswith('/'):
        raise ValueError('cannot wrap malformed rootless bootstrap arguments')
    if result.get('Program') and result['Program'] != arguments[0]:
        raise ValueError('rootless bootstrap Program/argv[0] disagree')
    result['Program']=DEVICE_PATH
    result['ProgramArguments']=[DEVICE_PATH,'--exec']+arguments
    return result


def launchd_transform(ctx,composed):
    from core.jailbreak_mode import selected_mode
    mode = selected_mode(getattr(ctx, 't', {}))
    if mode == 'rootful':
        from .rootful_bootstrap import DAEMON, job
    else:
        from .rootless_bootstrap.package import DAEMON,job
    prepare(ctx)
    result=deepcopy(composed)
    jobs=result.get('LaunchDaemons')
    if not isinstance(jobs,dict):
        raise ValueError('paleinfo launchd transform requires LaunchDaemons')
    original=job()
    expected=wrapped_job(original) if mode == 'rootful' else original
    accepted=(original,expected) if mode == 'rootful' else (original,)
    if jobs.get(DAEMON) not in accepted:
        raise ValueError('paleinfo must wrap the exact original rootless bootstrap job, not replace another owner')
    jobs[DAEMON]=expected
    return result


def signing_inputs(ctx):
    return dict(paths=[prepare(ctx)['helper']['path']],detached=[],cache_plans=[])


def deploy(ctx):
    from .trustcache import _matching_report
    package=prepare(ctx);helper=package['helper']
    if _matching_report(ctx,{helper['cdhash']:helper['hash_type']}) is None:
        raise ValueError('actual paleinfo helper not registered in the combined TrustCache')
    ctx.installation.mount_system()
    destination='/mnt6'+DEVICE_PATH
    ctx.ssh.deploy_path(helper['path'],destination,uid=0,gid=0)
    ctx.ssh.sh('/usr/sbin/chown 0:0 '+shlex.quote(destination)+' && chmod 755 '+shlex.quote(destination))
    if hashlib.sha256(ctx.ssh.sh('cat '+shlex.quote(destination))).hexdigest()!=helper['sha256']:
        raise ValueError('paleinfo helper transfer/readback mismatch')
