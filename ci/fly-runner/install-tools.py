"""Install only checksum-pinned executables; never extract archive paths."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request

for tool in json.loads(Path('/tmp/tools.json').read_text()):
    with urllib.request.urlopen(tool['url'], timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != tool['sha256']:
        raise RuntimeError(f"checksum mismatch: {tool['binary']}")
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        members = [m for m in archive if m.isfile() and Path(m.name).name == tool['binary']]
        if len(members) != 1:
            raise RuntimeError(f"ambiguous executable: {tool['binary']}")
        dest = Path('/usr/local/bin') / tool['binary']
        dest.write_bytes(archive.extractfile(members[0]).read())
        dest.chmod(0o755)
