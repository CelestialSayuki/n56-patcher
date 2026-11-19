"""iOS14-equivalent loopback :44 dropbear service, with local key-only access."""
from copy import copy
import base64
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
from ..rootless_bootstrap import artifacts as a, macho, sileo
from ..rootful_runtime import _inspect
from core.trustcache import TrustCache

HERE=Path(__file__).resolve().parent
BASE='/.n56-bootstrap/rootful'
LABEL='com.n56.rootful.sshd'
SETUP='''#!/bin/sh
set -eu
STATE=/var/lib/n56-rootful
BASE=/.n56-bootstrap/rootful
umask 077
mkdir -p "$STATE" /var/root/.ssh
chmod 700 /var/root/.ssh
# Unlock only this live rootful passwd database; authentication stays key-only.
if [ ! -f "$STATE/ssh-account-configured" ]; then
    secret="$STATE/root-password.once"
    trap 'rm -f "$secret"' EXIT HUP INT TERM
    /usr/libexec/n56-random-secret > "$secret"
    /usr/sbin/pw usermod root -h 0 < "$secret"
    rm -f "$secret"
    trap - EXIT HUP INT TERM
    /usr/sbin/pwd_mkdb -p /etc/master.passwd
    : > "$STATE/ssh-account-configured"
fi
if [ ! -s "$STATE/dropbear_rsa_host_key" ]; then
    /binpack/usr/bin/dropbearkey -t rsa -f "$STATE/dropbear_rsa_host_key"
fi
chmod 600 "$STATE/dropbear_rsa_host_key" /var/root/.ssh/authorized_keys
if ! /usr/libexec/n56-binpack/bin/launchctl print system/com.n56.rootful.sshd >/dev/null 2>&1; then
    /usr/libexec/n56-binpack/bin/launchctl bootstrap system "$BASE/ssh.plist"
fi
'''


def helper(out,source,name):
    root=out/'legacy-helpers';root.mkdir(parents=True,exist_ok=True)
    dest=root/name;stub=a.REPO/'tools/rootless-runtime/legacy-libSystem-ios12.tbd'
    ent=a.REPO/'tools/rootless-runtime/runtime.entitlements'
    sdk=subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip()
    obj=root/(name+'.o')
    subprocess.run(['xcrun','clang','-target','arm64-apple-ios12.0','-isysroot',sdk,
        '-Wno-incompatible-sysroot','-Wno-deprecated-declarations','-march=armv8-a','-mno-outline-atomics',
        '-Os','-Wall','-Wextra','-Werror','-c',str(source),'-o',str(obj)],check=True)
    subprocess.run(['xcrun','clang','-target','arm64-apple-ios12.0','-nostdlib','-Wno-incompatible-sysroot',
        str(obj),str(stub),'-Wl,-e,_main','-Wl,-platform_version,ios,12.0,12.0','-o',str(dest)],check=True)
    _inspect(dest)
    subprocess.run(['codesign','-s','-','-f','--timestamp=none','--digest-algorithm=sha256',
                    '--identifier','com.n56.ios15.'+name,'--entitlements',str(ent),str(dest)],check=True,capture_output=True)
    return dest


def material(out,public_key=None):
    spec=json.loads((HERE/'ssh-sources.json').read_text());assets=a.REPO/spec['root']
    files={};facts=[]
    for rel,expected in spec['files'].items():
        source=assets/rel
        if a.sha(source)!=expected:raise ValueError('iOS14 SSH source pin changed: '+rel)
        data,_=macho.device_slice(source.read_bytes())
        path=out/'legacy-ssh'/rel;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(0o755)
        ent=a.REPO/'tools/rootless-runtime/runtime.entitlements'
        # iOS14's packager likewise gives its shipped binpack a real ad-hoc seal.
        subprocess.run(['codesign','-s','-','-f','--timestamp=none','--digest-algorithm=sha256',
            '--identifier','com.n56.ios15.ssh.'+path.name,'--entitlements',str(ent),str(path)],check=True,capture_output=True)
        raw,f=macho.inspect(path.read_bytes());files['binpack/'+rel]=(raw,0o755);facts.append(dict(path=rel,source_sha256=expected,**f))
    raw=(assets/'usr/bin/dropbearmulti').read_bytes();alg='ed25519' if b'ssh-ed25519' in raw else 'rsa'
    private=None
    if public_key is None:
        directory=out/'ssh/client';directory.mkdir(parents=True,exist_ok=True);private=directory/('id_'+alg)
        if not private.exists():
            args=['ssh-keygen','-q','-t',alg,'-N','','-C','n56-ios15-rootful-client','-f',str(private)]
            if alg=='rsa':args[4:4]=['-b','3072']
            subprocess.run(args,check=True,capture_output=True)
        private.chmod(0o600);public_key=private.with_name(private.name+'.pub')
    public_key=Path(public_key);text=public_key.read_text().strip();parts=text.split()
    if len(parts)<2 or parts[0] not in ('ssh-ed25519','ssh-rsa','ecdsa-sha2-nistp256') or '\n' in text:raise ValueError('ordinary public SSH key required')
    base64.b64decode(parts[1],validate=True)
    daemon=dict(Label=LABEL,ProgramArguments=['/binpack/usr/sbin/dropbear','-F','-E','-s','-p','127.0.0.1:44',
        '-S','/binpack/bin/bash','-r','/var/lib/n56-rootful/dropbear_rsa_host_key'],UserName='root',RunAtLoad=True,
        KeepAlive=True,ThrottleInterval=10,EnvironmentVariables=dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin',HOME='/var/root'),
        StandardOutPath='/var/log/n56-rootful-sshd.log',StandardErrorPath='/var/log/n56-rootful-sshd.log')
    files.update({'private/var/root/.ssh/authorized_keys':((text+'\n').encode(),0o600),
                  BASE.lstrip('/')+'/setup-ssh.sh':(SETUP.encode(),0o755),
                  BASE.lstrip('/')+'/ssh.plist':(plistlib.dumps(daemon,fmt=plistlib.FMT_BINARY),0o644)})
    random=helper(out,a.REPO/'tools/rootless-runtime/random-secret.c','n56-random-secret')
    files['usr/libexec/n56-random-secret']=(random.read_bytes(),0o755)
    report=dict(baseline='ios14 dropbear loopback service',port=44,listen_address='127.0.0.1',
        authentication='publickey-only',public_key_sha256=a.sha(public_key),private_client_key=str(private) if private else None,
        host_key_generated_on_firstboot=True,daemon=daemon,source_pins=spec['files'],binary_facts=facts,
        runtime_validated=False,device_access=False)
    return files,report
