"""Registered iOS 15 wallpaper overlay; selection follows the actual 19H422 tree."""
from pathlib import Path

from core import log
from core.patch import Patch
from patches.ios15.impl.rootfs.ui_resources import MaterialError, source_roots, write_json
from patches.ios15.impl.rootfs.wallpaper import analyze_wallpaper, deploy_wallpaper


class Wallpaper(Patch):
    id = 'rootfs.wallpaper'
    layer = 'rootfs'
    role = 'overlay'
    feature = 'ui'
    requires = ('rootfs.base_stream',)
    after = ('rootfs.ui_resources',)
    donors = ('n66', 'j96')
    note = '实查 19H422 iPhone 414×736@3x 壁纸与默认表，保留 J96 Collections；验证完整后才删除 iPad 集'

    def apply(self, ctx, art=None):
        roots = source_roots(ctx)
        native = roots['n56']
        plan = analyze_wallpaper(roots['n66'], roots['j96'],
                                 n56=native if native is not None and native.is_dir() else None)
        manifest = Path(ctx.wk('wallpaper-manifest.json'))
        write_json(manifest, plan)
        ctx.patch_reports[self.id] = {
            'manifest': str(manifest), 'status': plan['status'], 'versions': plan['versions'],
            'copies': sum(item['op'] == 'copy' for item in plan['operations']),
            'deletes': sum(item['op'] == 'delete' for item in plan['operations']),
            'copy_bytes': plan['copy_bytes'], 'delete_bytes': plan['delete_bytes'],
            'net_bytes': plan['net_bytes'], 'blockers': plan['blockers'],
            'n56_default': plan.get('n56_default'),
        }
        if plan['blockers']:
            raise MaterialError('; '.join(plan['blockers']))
        log.log(f'  iOS 15 wallpaper: 净增 {plan["net_bytes"]} bytes')
        session = ctx.ssh
        session.mount(ctx.t['mounts']['system_b'], '/mnt6')
        deploy_wallpaper(session, roots['n66'], plan)
