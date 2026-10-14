"""Hash a locally built APK; records no unverified signer or security claim."""
import argparse
import hashlib
import json
from pathlib import Path
from .lab import _hex, _HEX40

def manifest(path,revision):
    if not _hex(revision,_HEX40):raise ValueError("concrete tested revision required")
    path=Path(path)
    if not path.is_file() or path.stat().st_size==0:raise ValueError("nonempty APK required")
    digest=hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda:source.read(1024*1024),b""):digest.update(chunk)
    return {"schema":1,"tested_revision":revision,"apk_sha256":digest.hexdigest(),
            "apk_size":path.stat().st_size,"signer_verification":"UNVERIFIED",
            "note":"Supply the actual checked-out build revision, including a PR merge revision when applicable. Verify signer separately."}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("apk");p.add_argument("--revision",required=True);args=p.parse_args(argv)
    try:print(json.dumps(manifest(args.apk,args.revision),indent=2));return 0
    except (OSError,ValueError) as exc:p.exit(2,str(exc)+"\n")
if __name__=="__main__":raise SystemExit(main())
