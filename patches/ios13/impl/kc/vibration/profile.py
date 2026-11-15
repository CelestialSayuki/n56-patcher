"""DRV2604 的 iOS 13.7 地址与布局。"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
PWM_META = 0xfffffff0077f0ae8


def donor_kernel(derived):
    """12 donor 内核（N56 12.5.8）在 derived 目录中的位置。"""
    return Path(derived) / 'extracted/n56ap_ios12/kernelcache.release.iphone7.decompressed'


def profile(derived, symbols):
    """derived 为从 IPSW 生成的输入目录；symbols 为本次输入内核的符号表 JSON（transplant.target_symbols 现算）。"""
    return dict(donor=donor_kernel(derived), pwm_meta=PWM_META,
                pwm_ctor=0xfffffff005fd9e74, pwm_dtor=0xfffffff005fd9e94,
                iic_vtable=0xfffffff006dcd078, pwm_meta_vtable=0xfffffff006dd9600,
                delay_function=0xfffffff0070efbc8, clock_global=0xfffffff0077f0490,
                const_host="__PLK_DATA_CONST", search_padding=False,
                symbols=Path(symbols), externs=HERE / "extern-map-12-to-13.json")
