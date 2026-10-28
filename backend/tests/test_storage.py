"""Object storage: the local backend end to end, and the URL contract for the cloud ones."""

from __future__ import annotations

import io

import pytest

from src import storage
from src.storage import LocalStore, StorageError


@pytest.fixture()
def store(tmp_path) -> LocalStore:
    return LocalStore(str(tmp_path / "store"))


def test_round_trip_and_uri(store: LocalStore) -> None:
    uri = store.put_file("exports/abc", io.BytesIO(b"rulebase"), "application/json")
    assert uri.endswith("/exports/abc") and uri.startswith("file://")
    assert store.exists("exports/abc")
    assert store.get_bytes("exports/abc") == b"rulebase"
    with store.open("exports/abc") as fh:
        assert fh.read() == b"rulebase"
    store.delete("exports/abc")
    assert not store.exists("exports/abc")


def test_a_missing_object_is_a_storage_error(store: LocalStore) -> None:
    with pytest.raises(StorageError, match="no object"):
        store.get_bytes("exports/none")


@pytest.mark.parametrize("key", ["../etc/passwd", "a/../../b", "/abs", "a//b", "", ".hidden", "a b"])
def test_keys_that_could_escape_the_prefix_are_refused(store: LocalStore, key: str) -> None:
    with pytest.raises(StorageError, match="invalid storage key"):
        store.put_bytes(key, b"x", "text/plain")


def test_a_failed_write_leaves_no_partial_object(store: LocalStore) -> None:
    class Broken(io.BytesIO):
        def read(self, *_a):
            raise OSError("disk went away")

    with pytest.raises(OSError):
        store.put_file("exports/half", Broken(), "text/plain")
    assert not store.exists("exports/half")
    assert not [p for p in store.root.rglob(".tmp-*")]


def test_sha256_is_chunked_and_rewinds() -> None:
    fh = io.BytesIO(b"abc")
    digest, size = storage.sha256_file(fh)
    assert digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert size == 3 and fh.tell() == 0


def test_url_dispatch(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    built = {}
    monkeypatch.setattr(storage, "GCSStore", lambda b, p: built.setdefault("gs", (b, p)))
    monkeypatch.setattr(storage, "AzureBlobStore", lambda a, c, p: built.setdefault("az", (a, c, p)))
    storage.from_url("gs://frr-exports/prod")
    storage.from_url("az://frrstore/exports/prod")
    assert built == {"gs": ("frr-exports", "/prod"), "az": ("frrstore", "exports", "prod")}
    assert isinstance(storage.from_url(f"file://{tmp_path}"), LocalStore)
    with pytest.raises(StorageError, match="container"):
        storage.from_url("az://frrstore")
    with pytest.raises(StorageError, match="unsupported"):
        storage.from_url("s3://bucket")
