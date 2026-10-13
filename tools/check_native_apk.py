"""Verify the shipped ABIs and the bounded, owned function ranges used for baselines."""
import os
import subprocess
from pathlib import Path
from zipfile import ZipFile

ABIS = {"arm64-v8a", "armeabi-v7a", "x86_64"}
apk = Path("android/scanner/build/outputs/apk/release/scanner-release.apk")
with ZipFile(apk) as z:
    libs = {name.split("/")[1] for name in z.namelist() if name.endswith("/libdtnative.so")}
    assert libs == ABIS, libs
sdk = Path(os.environ["ANDROID_HOME"])
nm = sdk / "ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-nm"
checked = set()
for lib in Path("android/devicetrust").rglob("libdtnative.so"):
    if "/obj/" not in lib.as_posix():
        continue
    abi = lib.parent.name
    if abi not in ABIS:
        continue
    output = subprocess.check_output([str(nm), "--print-size", "--defined-only", str(lib)], text=True)
    sizes = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[-1] in {"dt_collect", "dt_read", "dt_tracer"}:
            sizes[parts[-1]] = int(parts[1], 16)
    assert len(sizes) == 3 and all(size >= 16 for size in sizes.values()), (lib, sizes)
    checked.add(abi)
assert checked == ABIS, checked
print("Native ABI packaging and all nine owned code ranges verified")
