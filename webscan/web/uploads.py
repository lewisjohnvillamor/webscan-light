"""Safe handling of uploaded project archives for the web code-scan flow.

Extracting an attacker-supplied zip is dangerous: path traversal (Zip-Slip),
zip bombs and symlink tricks. This extracts into an isolated temp directory with
hard limits and never writes outside it. Used only for the local-filesystem
tools (code / secrets / deps) so web users can scan an uploaded project without
the server ever touching its own filesystem.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

MAX_FILES = 20000
MAX_TOTAL_BYTES = 200 * 1024 * 1024      # 200 MB uncompressed
MAX_FILE_BYTES = 25 * 1024 * 1024        # 25 MB per file
MAX_ZIP_BYTES = 60 * 1024 * 1024         # 60 MB compressed upload


class UploadError(Exception):
    pass


def _safe_join(dest: Path, name: str) -> Path | None:
    # Reject absolute paths, drive letters and parent traversal.
    if name.startswith(("/", "\\")) or ":" in name.split("/", 1)[0]:
        return None
    target = (dest / name).resolve()
    try:
        target.relative_to(dest.resolve())
    except ValueError:
        return None
    return target


def extract_zip(zip_path: str, dest: str) -> tuple[int, int]:
    """Extract ``zip_path`` into ``dest`` safely. Returns (files, bytes)."""
    destp = Path(dest)
    destp.mkdir(parents=True, exist_ok=True)
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise UploadError("Not a valid .zip archive.") from exc

    files = total = 0
    with zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_FILES:
            raise UploadError(f"Archive has too many files (> {MAX_FILES}).")
        if sum(i.file_size for i in infos) > MAX_TOTAL_BYTES:
            raise UploadError("Archive is too large uncompressed (possible zip bomb).")
        for info in infos:
            if info.file_size > MAX_FILE_BYTES:
                continue  # skip oversized single files rather than fail the whole scan
            target = _safe_join(destp, info.filename)
            if target is None:
                raise UploadError(f"Unsafe path in archive: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with zf.open(info) as src, open(target, "wb") as out:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_FILE_BYTES:
                        break
                    total += len(chunk)
                    if total > MAX_TOTAL_BYTES:
                        raise UploadError("Archive is too large uncompressed (possible zip bomb).")
                    out.write(chunk)
            files += 1
    return files, total
