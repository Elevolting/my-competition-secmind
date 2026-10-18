"""Download the pinned official Community JAR with resumable HTTP ranges."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import shutil
import time
import urllib.request
import zipfile
import hashlib

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / '_runtime/tools/burp'
URL = 'https://portswigger.net/burp/releases/download?product=community&version=2026.3.3&type=Jar'
SIZE = 684704951


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    final = DEST / 'burpsuite-community.jar'
    if final.exists() and final.stat().st_size == SIZE:
        with zipfile.ZipFile(final) as archive:
            if archive.testzip() is None:
                print('Burp Community is already complete.', flush=True)
                return
    partial = DEST / 'burpsuite-community.jar.partial'
    prefix = partial.stat().st_size if partial.exists() else 0
    if prefix > SIZE:
        raise ValueError('Partial download exceeds the expected release size')
    parts = DEST / 'download-parts'
    parts.mkdir(exist_ok=True)
    ranges = [(start, min(start + 8 * 1024 * 1024, SIZE) - 1)
              for start in range(prefix, SIZE, 8 * 1024 * 1024)]

    def download(bounds):
        start, end = bounds
        part = parts / f'{start}-{end}.part'
        length = end - start + 1
        for attempt in range(6):
            have = part.stat().st_size if part.exists() else 0
            if have == length:
                return part
            if have > length:
                raise ValueError(f'Unexpected part length: {part}')
            try:
                request = urllib.request.Request(URL, headers={'Range': f'bytes={start + have}-{end}'})
                with urllib.request.urlopen(request, timeout=40) as response:
                    expected = f'bytes {start + have}-{end}/{SIZE}'
                    if response.status != 206 or response.headers.get('Content-Range') != expected:
                        raise ValueError('Server returned an unexpected HTTP byte range')
                    with part.open('ab') as output:
                        shutil.copyfileobj(response, output, length=256 * 1024)
                if part.stat().st_size != length:
                    raise ValueError('Incomplete byte range')
                print(f'Downloaded bytes {start}-{end}', flush=True)
                return part
            except Exception as error:
                if attempt == 5:
                    raise
                print(f'Retrying bytes {start}-{end}: {type(error).__name__}', flush=True)
                time.sleep(2)

    with ThreadPoolExecutor(max_workers=12) as pool:
        downloaded = list(pool.map(download, ranges))
    # Keep the original prefix and parts intact until validation succeeds.
    assembled = DEST / 'burpsuite-community.jar.assembling'
    with assembled.open('wb') as output:
        if prefix:
            with partial.open('rb') as source:
                shutil.copyfileobj(source, output)
        for part in downloaded:
            with part.open('rb') as source:
                shutil.copyfileobj(source, output)
    if assembled.stat().st_size != SIZE:
        raise ValueError('Unexpected final length')
    with zipfile.ZipFile(assembled) as archive:
        bad = archive.testzip()
        if bad:
            raise ValueError(f'JAR CRC check failed: {bad}')
    assembled.replace(final)
    digest = hashlib.sha256(final.read_bytes()).hexdigest()
    (DEST / 'release.json').write_text(json.dumps({
        'version': '2026.3.3', 'source': URL, 'bytes': SIZE,
        'sha256': digest, 'validation': 'all ZIP entry CRCs verified',
    }, indent=2), encoding='utf-8')
    print(f'Burp Community complete, ZIP CRC verified, SHA256={digest}', flush=True)


if __name__ == '__main__':
    main()
