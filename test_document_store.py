import pytest
import document_store
from document_store import read_document_file

@pytest.mark.parametrize(
    "filename",
    [
        "../.env",
        "../../secrets.txt",
        "/etc/passwd",
        "folder/secret.txt",
        r"..\secret.txt",
        ".env",
        "",
    ],
)
def test_unsafe_file_paths_are_rejected(filename):
    with pytest.raises(ValueError):
        read_document_file(filename)

def test_symlink_cannot_escape_document_root(tmp_path, monkeypatch):

    protected = tmp_path / "protected_documents"
    protected.mkdir()

    secret = tmp_path / "secret.txt"
    secret.write_text("CONFIDENTIAL TEST DATA")

    link = protected / "shortcut.txt"
    link.symlink_to(secret)

    monkeypatch.setattr(document_store, "DOCUMENT_ROOT", protected)

    with pytest.raises((ValueError, PermissionError)):
        document_store.read_document_file("shortcut.txt")


def test_symlink_cannot_update_outside_document_root(
    tmp_path, monkeypatch
):

    protected = tmp_path / "protected_documents"
    protected.mkdir()

    secret = tmp_path / "secret.txt"
    secret.write_text("ORIGINAL SECRET")

    link = protected / "shortcut.txt"
    link.symlink_to(secret)

    monkeypatch.setattr(
        document_store,
        "DOCUMENT_ROOT",
        protected,
    )

    with pytest.raises((ValueError, PermissionError)):
        document_store.update_document_file(
            "shortcut.txt",
            "MALICIOUS UPDATE",
        )

    assert secret.read_text() == "ORIGINAL SECRET"


def test_failed_replace_preserves_original_document(
    tmp_path, monkeypatch
):

    protected = tmp_path / "protected_documents"
    protected.mkdir()

    document = protected / "report.txt"
    document.write_text("ORIGINAL CONTENT")

    monkeypatch.setattr(
        document_store,
        "DOCUMENT_ROOT",
        protected,
    )

    def simulate_replace_failure(*args, **kwargs):
        raise OSError("Simulated disk operation failure")

    monkeypatch.setattr(
        document_store.os,
        "replace",
        simulate_replace_failure,
    )

    with pytest.raises(OSError):
        document_store.update_document_file(
            "report.txt",
            "NEW CONTENT",
        )

    assert document.read_text() == "ORIGINAL CONTENT"
    assert sorted(p.name for p in protected.iterdir()) == ["report.txt"]
