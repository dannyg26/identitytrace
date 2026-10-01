"""Locate bundled assets in a checkout or a standard wheel installation."""

import sysconfig
from pathlib import Path


def resource_directory(name: str) -> Path:
    checkout = Path(__file__).resolve().parent.parent / name
    if checkout.is_dir():
        return checkout
    return Path(sysconfig.get_path("data")) / "share" / "identitytrace" / name
