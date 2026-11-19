"""Registered 19H422 resource overlay using Context mounts or explicit external sources."""
from pathlib import Path

from core import log
from core.patch import Patch
from patches.ios15.impl.rootfs.ui_resources import (
    MaterialError, analyze_ui, audit_staged, cache_images, deploy_files, source_roots, write_json)


class UiResources(Patch):
    id = 'rootfs.ui_resources'
    layer = 'rootfs'
    role = 'overlay'
    feature = 'ui'
    requires = ('rootfs.base_stream',)
    donors = ('n66', 'j96')
    note = '19H422 iPhone 数据资源；保留 J96 A8 代码/cache/签名，staged apps 逐包审计并等待重新封签'

    def apply(self, ctx, art=None):
        roots = source_roots(ctx)  # Context manages production mount ownership/reuse.
        images = cache_images(roots['j96'])
        plan = analyze_ui(roots['n66'], roots['j96'], images=images, donor_images=cache_images(roots['n66']))
        staged = audit_staged(roots['n66'], roots['j96'], images=images)
        manifest = Path(ctx.wk('ui-manifest.json'))
        staged_manifest = Path(ctx.wk('staged-apps-audit.json'))
        write_json(manifest, plan)
        write_json(staged_manifest, staged)
        incomplete = any(v == 'missing-or-rejected' for v in plan['required'].values())
        ctx.patch_reports[self.id] = {
            'status': 'blocked-ui' if incomplete else 'verified-resource-plan',
            'manifest': str(manifest), 'staged_apps_manifest': str(staged_manifest),
            'versions': plan['versions'], 'required': plan['required'],
            'files': len(plan['operations']), 'bytes': plan['bytes'],
            'staged': staged['counts'], 'unsigned_placeholder_files': len(staged['operations']),
        }
        if incomplete:
            raise MaterialError('required iPhone UI data missing/rejected; inspect ui-manifest.json')
        log.log(f'  iOS 15: {len(plan["operations"])} 份数据资源；staged 审计 {staged["counts"]}')
        session = ctx.ssh
        session.mount(ctx.t['mounts']['system_b'], '/mnt6')
        deploy_files(session, roots['n66'], plan['operations'])
        if staged['counts'].get('deferred-reseal'):
            log.log('  签名 staged 资源由 rootfs.staged_apps 封签/登记；本步骤仅更新核验通过的无签名占位资源')
        # Only unsigned placeholder data; signed staged app candidates remain deferred.
        deploy_files(session, roots['n66'], staged['operations'])
        # Deliberately no staged_apps.deploy(): it copies donor code and signature seals.
        session.sync()
