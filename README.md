# Exotherm

Exotherm is a PySide6 desktop application for encrypting and decrypting individual files or recursive folders. It uses a password-derived key with AES-GCM authenticated encryption and stores encrypted files with the `.exotherm` extension.

## Run

Requires Python 3.14 or newer and [uv](https://docs.astral.sh/uv/). From the project folder:

```powershell
uv sync
uv run exotherm
```

## At a glance

- Drag and drop or browse for a file or folder, enter a password, then choose encrypt or decrypt.
- Folder operations process up to two files concurrently. A file error or password mismatch does not stop the other files.
- Existing destination files are not overwritten. The GUI reports successes, skips, and failures, and warns users not to close it during an operation.

## Security status

This project has not been professionally audited. It is not a secure file shredder: deleting a file does not guarantee that its data is erased from an SSD. Decryption uses a plaintext temporary file before publishing the output. A crash or power loss can leave temporary data behind. Full-drive encryption can help protect data at rest while the device is locked, but does not protect plaintext while the computer is unlocked or in use.

## Technical details (in depth)

### Component flow

1. `gui.py` collects the selected path and password and starts `FileOperationWorker`, a PySide6 `QThread`.
2. The worker calls `backend_tieup.process_path()` and sends a structured result back to the GUI for status text and popups.
3. For folders, the backend discovers files recursively and submits each candidate to a `ThreadPoolExecutor` with a maximum of two active file tasks.
4. Each file task uses `key.py` for key derivation and `aes.py` for AES-GCM encryption or decryption.

### Key derivation and encrypted format

- Password text is encoded as UTF-8.
- `key.create_key()` uses Argon2id (`Type.ID`): time cost 3, memory cost 65,536 KiB, parallelism 4, and a 32-byte derived key.
- Encryption generates a random 16-byte salt and a random 12-byte AES-GCM nonce.
- The `.exotherm` file is the concatenation `nonce (12 bytes) + salt (16 bytes) + ciphertext (including the GCM authentication tag)`. The current format has no separate version header.
- During decryption, AES-GCM validates the authentication tag before returning plaintext. A wrong password or modified data fails authentication; the encrypted source is left in place.

### Batch behavior and errors

- The backend validates file type and destination paths; the GUI displays the resulting errors and batch summary.
- Folder encryption considers files that do not end in `.exotherm`; folder decryption considers `.exotherm` files.
- Existing destination paths are reported as skipped. A wrong-password or damaged encrypted file is left unchanged while the remaining candidates are processed.
- Each candidate returns a `FileOutcome` (`success`, `skipped`, or `failed`). `BatchResult` aggregates outcomes, so one file failure does not terminate the batch.
- Two concurrent file tasks are allowed because each key derivation uses 64 MiB of memory.

### Atomic output and cleanup

For each file, the backend follows this sequence:

1. Validate that the source is usable and the destination does not already exist.
2. Read the source with a context-managed file handle. The current implementation reads each whole file into memory.
3. Create a uniquely named temporary file in the destination directory, write the completed output, flush it, and call `fsync`.
4. Publish the completed temp file without overwriting: the backend tries `os.link` and unlinks the temp name; if Windows denies hard-link creation, it falls back to same-volume `os.rename`.
5. Delete the original source only after the destination has been published.

The write helper uses a `finally` block to remove the temp path if writing or publishing raises an error. Context managers close file handles, the executor context waits for tasks and shuts down its threads, and the Qt worker clears its password reference when it exits. The GUI retains the worker until its `QThread.finished` signal and blocks window closing while the operation is active.

These steps provide best-effort cleanup during normal completion and handled errors; abrupt termination can bypass cleanup, and permissions or disk errors can prevent deletion. On decryption, the temp output contains plaintext. On encryption, the original plaintext source remains until the encrypted output is published and is then ordinarily deleted. Neither deletion guarantees secure erasure from SSD storage. If deleting the source fails after publication, both source and output may remain.

### Verification

Python compilation and manual smoke checks have been run for batch encryption, mixed-password decryption, and per-file failure isolation. The project currently has no automated test suite and has not received a professional security audit.
