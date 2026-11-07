"""DRV2604 的 iOS 13.7 地址与布局。"""
from pathlib import Path
from patches.shared.impl.paths import N56

HERE = Path(__file__).resolve().parent


def profile():
    return dict(donor=N56, pwm_meta=0xfffffff0077f0ae8,
                pwm_ctor=0xfffffff005fd9e74, pwm_dtor=0xfffffff005fd9e94,
                iic_vtable=0xfffffff006dcd078, pwm_meta_vtable=0xfffffff006dd9600,
                delay_function=0xfffffff0070efbc8, clock_global=0xfffffff0077f0490,
                const_host="__PLK_DATA_CONST", search_padding=False,
                symbols=HERE / "target-symbols.json", externs=HERE / "extern-map-12-to-13.json")
