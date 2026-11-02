
from pathlib import Path
import os
import tempfile

DOCUMENT_ROOT = (
    Path(__file__).resolve().parent / "protected_documents"
).resolve()


def read_document_file(filename: str) -> str:
    """Read a document from protected storage."""

    if not isinstance(filename, str):
        raise ValueError("Invalid filename")

    if (
        not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or not filename.endswith(".txt")
    ):
        raise ValueError("Invalid filename")

    path = (DOCUMENT_ROOT / filename).resolve()

    if not path.is_relative_to(DOCUMENT_ROOT):
        raise PermissionError("Access outside document storage denied")

    if not path.is_file():
        raise FileNotFoundError("Document not found")

    if path.stat().st_size > 100_000:
        raise ValueError("Document exceeds size limit")

    return path.read_text(encoding="utf-8")


def update_document_file(filename: str, new_content: str) -> None:
    """Safely replace a document inside protected storage."""

    if not isinstance(new_content, str):
        raise ValueError("Document content must be text")

    if len(new_content.encode("utf-8")) > 100_000:
        raise ValueError("Document exceeds size limit")

    if (
        not isinstance(filename, str)
        or not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or not filename.endswith(".txt")
    ):
        raise ValueError("Invalid filename")

    path = (DOCUMENT_ROOT / filename).resolve()

    if not path.is_relative_to(DOCUMENT_ROOT):
        raise PermissionError("Access outside document storage denied")

    if not path.is_file():
        raise FileNotFoundError("Document not found")

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=DOCUMENT_ROOT,
            prefix=".agentshield-",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temp_path = temporary.name
            temporary.write(new_content)
            temporary.flush()
            os.fsync(temporary.fileno())

        os.replace(temp_path, path)

    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
