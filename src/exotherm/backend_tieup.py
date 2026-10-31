"""File operations for Exotherm.

The on-disk format remains ``nonce (12 bytes) + salt (16 bytes) + AES-GCM
ciphertext``. Output is written beside its source and only committed after the
whole operation succeeds, so an interrupted write cannot replace the source.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import os
import tempfile
from typing import Literal

from cryptography.exceptions import InvalidTag

try:  # Package import; the fallback also supports running this module directly.
    from .aes import decrypt, encrypt
    from .key import create_key
except ImportError:  # pragma: no cover - compatibility for direct module use
    from aes import decrypt, encrypt
    from key import create_key

suffix = ".exotherm"
MAX_PARALLEL_FILES = 2  # Each Argon2 derivation uses 64 MiB.


class WrongPasswordOrCorruptFileError(ValueError):
    """AES-GCM authentication failed: the password or file contents are wrong."""


@dataclass
class FileOutcome:
    path: str
    status: Literal["success", "skipped", "failed"]
    message: str = ""
    output_path: str | None = None


@dataclass
class BatchResult:
    action: Literal["encrypt", "decrypt"]
    outcomes: list[FileOutcome] = field(default_factory=list)
    candidates: int = 0
    wrong_password_or_corrupt: int = 0

    @property
    def succeeded(self) -> int:
        return sum(item.status == "success" for item in self.outcomes)

    @property
    def skipped(self) -> int:
        return sum(item.status == "skipped" for item in self.outcomes)

    @property
    def failed(self) -> int:
        return sum(item.status == "failed" for item in self.outcomes)


def _commit_without_overwrite(temp_path: str, target_path: str) -> None:
    """Atomically publish a completed temp file, refusing to overwrite targets."""
    # A hard link is an atomic create-if-absent operation on POSIX. Windows can
    # disallow hard links in restricted folders; os.rename there also fails if
    # the destination exists, and the temp file is on the same volume.
    try:
        os.link(temp_path, target_path)
    except (NotImplementedError, PermissionError):
        if os.name != "nt":
            raise
        os.rename(temp_path, target_path)
    else:
        os.unlink(temp_path)


def _write_atomic(target_path: str, content: bytes) -> None:
    target_dir = os.path.dirname(os.path.abspath(target_path))
    fd, temp_path = tempfile.mkstemp(prefix=".exotherm-", suffix=".tmp", dir=target_dir)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        _commit_without_overwrite(temp_path, target_path)
    finally:
        # If writing or publishing fails, clean up the incomplete temporary file.
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass


def _validate_source(path: str, action: Literal["encrypt", "decrypt"]) -> str:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")
    if action == "decrypt" and not path.endswith(suffix):
        raise ValueError("Selected file does not have the correct .exotherm extension.")
    if action == "encrypt" and path.endswith(suffix):
        raise ValueError("The file is already encrypted.")
    target = path.removesuffix(suffix) if action == "decrypt" else path + suffix
    if os.path.exists(target):
        raise FileExistsError(f"A file named {os.path.basename(target)} already exists.")
    return target


def encrypt_file(file: str, password: bytes) -> str:
    """Encrypt one file with the unchanged Argon2 + AES-GCM format."""
    target = _validate_source(file, "encrypt")
    with open(file, "rb") as source:
        content = source.read()
    key, salt = create_key(password)
    ciphertext, nonce = encrypt(content, key)
    _write_atomic(target, nonce + salt + ciphertext)
    # Keep the original intact until the encrypted output is fully committed.
    os.unlink(file)
    return target


def decrypt_file(enc_file: str, password: bytes) -> str:
    """Decrypt one file; authentication and output creation precede source removal."""
    target = _validate_source(enc_file, "decrypt")
    with open(enc_file, "rb") as source:
        blob = source.read()
    if len(blob) < 28 + 16:  # nonce + salt + minimum GCM authentication tag
        raise ValueError("The encrypted file is too short or damaged.")
    nonce, salt, ciphertext = blob[:12], blob[12:28], blob[28:]
    key, _ = create_key(password, salt)
    try:
        plaintext = decrypt(ciphertext, key, nonce)
    except InvalidTag as exc:
        raise WrongPasswordOrCorruptFileError(
            "The password is incorrect or the encrypted file is damaged."
        ) from exc
    _write_atomic(target, plaintext)
    os.unlink(enc_file)
    return target


def _process_one(path: str, password: bytes, action: Literal["encrypt", "decrypt"]) -> FileOutcome:
    if action == "decrypt" and not path.endswith(suffix):
        return FileOutcome(path, "skipped", "Not an .exotherm file.")
    if action == "encrypt" and path.endswith(suffix):
        return FileOutcome(path, "skipped", "Already encrypted.")
    try:
        result_path = encrypt_file(path, password) if action == "encrypt" else decrypt_file(path, password)
        return FileOutcome(path, "success", output_path=result_path)
    except WrongPasswordOrCorruptFileError as exc:
        # Authentication failure means this file is intentionally left alone
        # while the rest of a folder batch continues.
        return FileOutcome(path, "skipped", str(exc))
    except FileExistsError as exc:
        return FileOutcome(path, "skipped", str(exc))
    except (OSError, ValueError) as exc:
        return FileOutcome(path, "failed", str(exc) or exc.__class__.__name__)
    except Exception as exc:  # Isolate unexpected per-file failures from the rest of the batch.
        return FileOutcome(path, "failed", f"Unexpected error: {exc}")


def _collect_files(path: str) -> tuple[list[str], list[FileOutcome]]:
    files: list[str] = []
    errors: list[FileOutcome] = []

    def on_walk_error(error: OSError) -> None:
        errors.append(FileOutcome(getattr(error, "filename", None) or path, "failed", str(error)))

    for root, _, names in os.walk(path, onerror=on_walk_error):
        for name in names:
            files.append(os.path.join(root, name))
    return files, errors


def process_path(path: str, password: bytes, action: Literal["encrypt", "decrypt"]) -> BatchResult:
    """Process a file or directory; one failed file never stops the other files."""
    if action not in ("encrypt", "decrypt"):
        raise ValueError("Action must be 'encrypt' or 'decrypt'.")
    if os.path.isfile(path):
        paths, walk_errors = [path], []
    elif os.path.isdir(path):
        paths, walk_errors = _collect_files(path)
    else:
        raise FileNotFoundError(f"Selected file or folder does not exist: {path}")

    if os.path.isfile(path):
        # Single-file misuse remains an actionable error in the GUI.
        _validate_source(path, action)

    candidates = [p for p in paths if p.endswith(suffix) == (action == "decrypt")]
    result = BatchResult(action=action, candidates=len(candidates), outcomes=walk_errors)
    if not candidates:
        return result

    with ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_FILES, len(candidates)),
                            thread_name_prefix="exotherm-file") as pool:
        futures = {pool.submit(_process_one, item, password, action): item for item in candidates}
        for future in as_completed(futures):
            path_for_future = futures[future]
            try:
                outcome = future.result()
            except Exception as exc:  # Defensive boundary around the worker executor.
                outcome = FileOutcome(path_for_future, "failed", f"Unexpected error: {exc}")
            result.outcomes.append(outcome)
            if action == "decrypt" and (
                "password is incorrect" in outcome.message or "damaged" in outcome.message
            ):
                result.wrong_password_or_corrupt += 1
    return result
