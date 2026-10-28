"""Object storage for uploaded exports and published snapshot artifacts.

One small interface over three backends, chosen by `NPR_STORAGE_URL`:

    file:///abs/path              local directory (dev, tests)       -- default
    gs://bucket[/prefix]          Google Cloud Storage
    az://account/container[/prefix]  Azure Blob Storage

Authentication is the platform's workload identity in every cloud case -- ADC
on GCP, DefaultAzureCredential on Azure -- so no storage key exists to leak.

KEYS ARE CONTENT ADDRESSES, NOT PATHS FROM USERS
------------------------------------------------
Callers build keys from hashes and ids (`exports/<sha256>`), never from an
uploaded filename. `_check_key` still refuses anything that could walk out of
the prefix, because the local backend maps keys onto a real filesystem.

STREAMING
---------
`put_file` takes a file object and never reads it whole: an upload is spooled
by the web server and streamed to the backend in chunks, so a 500 MB export does
not need 500 MB of API memory. `put_bytes` is for small artifacts only.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
import threading
from pathlib import Path
from typing import BinaryIO, Protocol
from urllib.parse import urlparse

from . import settings

_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")
_CHUNK = 8 * 1024 * 1024


class StorageError(RuntimeError):
    pass


def _check_key(key: str) -> str:
    if not _KEY_RE.match(key) or ".." in key.split("/") or "//" in key:
        raise StorageError(f"invalid storage key {key!r}")
    return key


class BlobStore(Protocol):
    uri_prefix: str

    def put_file(self, key: str, fileobj: BinaryIO, content_type: str) -> str: ...
    def put_bytes(self, key: str, data: bytes, content_type: str) -> str: ...
    def get_bytes(self, key: str) -> bytes: ...
    def open(self, key: str) -> BinaryIO: ...
    def exists(self, key: str) -> bool: ...
    def delete(self, key: str) -> None: ...


class LocalStore:
    """A directory. Writes go to a temp file and are renamed, so a reader never
    sees half an object -- the same atomicity the cloud stores give."""

    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.uri_prefix = f"file://{self.root}"

    def _path(self, key: str) -> Path:
        p = (self.root / _check_key(key)).resolve()
        if self.root not in p.parents:
            raise StorageError(f"invalid storage key {key!r}")
        return p

    def put_file(self, key: str, fileobj: BinaryIO, content_type: str) -> str:
        dest = self._path(key)
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as out:
                shutil.copyfileobj(fileobj, out, _CHUNK)
            os.replace(tmp, dest)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return f"{self.uri_prefix}/{key}"

    def put_bytes(self, key: str, data: bytes, content_type: str) -> str:
        import io
        return self.put_file(key, io.BytesIO(data), content_type)

    def get_bytes(self, key: str) -> bytes:
        try:
            return self._path(key).read_bytes()
        except FileNotFoundError as e:
            raise StorageError(f"no object {key!r}") from e

    def open(self, key: str) -> BinaryIO:
        try:
            return self._path(key).open("rb")
        except FileNotFoundError as e:
            raise StorageError(f"no object {key!r}") from e

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)


class GCSStore:
    def __init__(self, bucket: str, prefix: str) -> None:
        from google.cloud import storage as gcs

        self._bucket = gcs.Client().bucket(bucket)
        self._prefix = prefix.strip("/")
        self.uri_prefix = f"gs://{bucket}" + (f"/{self._prefix}" if self._prefix else "")

    def _name(self, key: str) -> str:
        key = _check_key(key)
        return f"{self._prefix}/{key}" if self._prefix else key

    def put_file(self, key: str, fileobj: BinaryIO, content_type: str) -> str:
        blob = self._bucket.blob(self._name(key), chunk_size=_CHUNK)
        blob.upload_from_file(fileobj, content_type=content_type, rewind=False)
        return f"{self.uri_prefix}/{key}"

    def put_bytes(self, key: str, data: bytes, content_type: str) -> str:
        self._bucket.blob(self._name(key)).upload_from_string(data, content_type=content_type)
        return f"{self.uri_prefix}/{key}"

    def get_bytes(self, key: str) -> bytes:
        from google.api_core.exceptions import NotFound
        try:
            return self._bucket.blob(self._name(key)).download_as_bytes()
        except NotFound as e:
            raise StorageError(f"no object {key!r}") from e

    def open(self, key: str) -> BinaryIO:
        return self._bucket.blob(self._name(key)).open("rb")

    def exists(self, key: str) -> bool:
        return self._bucket.blob(self._name(key)).exists()

    def delete(self, key: str) -> None:
        from google.api_core.exceptions import NotFound
        try:
            self._bucket.blob(self._name(key)).delete()
        except NotFound:
            pass


class AzureBlobStore:
    def __init__(self, account: str, container: str, prefix: str) -> None:
        from azure.identity import DefaultAzureCredential
        from azure.storage.blob import BlobServiceClient

        svc = BlobServiceClient(f"https://{account}.blob.core.windows.net",
                                credential=DefaultAzureCredential())
        self._container = svc.get_container_client(container)
        self._prefix = prefix.strip("/")
        self.uri_prefix = f"az://{account}/{container}" + (f"/{self._prefix}" if self._prefix else "")

    def _name(self, key: str) -> str:
        key = _check_key(key)
        return f"{self._prefix}/{key}" if self._prefix else key

    def put_file(self, key: str, fileobj: BinaryIO, content_type: str) -> str:
        from azure.storage.blob import ContentSettings
        self._container.upload_blob(self._name(key), fileobj, overwrite=True,
                                    max_concurrency=4,
                                    content_settings=ContentSettings(content_type=content_type))
        return f"{self.uri_prefix}/{key}"

    def put_bytes(self, key: str, data: bytes, content_type: str) -> str:
        import io
        return self.put_file(key, io.BytesIO(data), content_type)

    def get_bytes(self, key: str) -> bytes:
        from azure.core.exceptions import ResourceNotFoundError
        try:
            return self._container.download_blob(self._name(key)).readall()
        except ResourceNotFoundError as e:
            raise StorageError(f"no object {key!r}") from e

    def open(self, key: str) -> BinaryIO:
        import io
        return io.BytesIO(self.get_bytes(key))

    def exists(self, key: str) -> bool:
        return self._container.get_blob_client(self._name(key)).exists()

    def delete(self, key: str) -> None:
        self._container.delete_blob(self._name(key), delete_snapshots="include") \
            if self.exists(key) else None


def from_url(url: str) -> BlobStore:
    u = urlparse(url)
    if u.scheme == "file":
        return LocalStore(u.path)
    if u.scheme == "gs" and u.netloc:
        return GCSStore(u.netloc, u.path)
    if u.scheme == "az" and u.netloc:
        container, _, prefix = u.path.strip("/").partition("/")
        if not container:
            raise StorageError("az:// storage URL needs a container: az://account/container[/prefix]")
        return AzureBlobStore(u.netloc, container, prefix)
    raise StorageError(f"unsupported NPR_STORAGE_URL {url!r} (file://, gs://, az://)")


_STORE: BlobStore | None = None
_STORE_LOCK = threading.Lock()


def store() -> BlobStore:
    """The process's store, built once (clients hold connection pools)."""
    global _STORE
    with _STORE_LOCK:
        if _STORE is None:
            _STORE = from_url(settings.NPR_STORAGE_URL)
        return _STORE


def reset_store() -> None:
    global _STORE
    with _STORE_LOCK:
        _STORE = None


def sha256_file(fileobj: BinaryIO) -> tuple[str, int]:
    """(hex digest, size) of a seekable file, read in chunks and rewound."""
    h, n = hashlib.sha256(), 0
    fileobj.seek(0)
    while chunk := fileobj.read(_CHUNK):
        h.update(chunk)
        n += len(chunk)
    fileobj.seek(0)
    return h.hexdigest(), n
