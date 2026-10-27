"""
CipherNest - Secure Cloud Storage Backend (FastAPI)
===================================================
A zero-knowledge encrypted cloud storage service.
Files are split into blocks and encrypted with AES-256-GCM before storage
in a private Amazon S3 bucket.

Security guarantees:
- Master encryption keys and AWS credentials NEVER leave the backend.
- Chunks are encrypted independently with unique nonces and AAD binding.
- Zero public access to the S3 bucket.
"""

import os
import sys
import uuid
import base64
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from crypto import CipherService, CryptoError, TamperingDetectedError
from storage import get_storage_backend, BaseStorage

# Setup structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ciphernest")

# Load environment configuration
load_dotenv()

CIPHERNEST_ENCRYPTION_KEY = os.getenv("CIPHERNEST_ENCRYPTION_KEY", "")
CHUNK_SIZE_BYTES = int(os.getenv("CHUNK_SIZE_BYTES", str(5 * 1024 * 1024))) # 5 MB default
MAX_FILE_SIZE_BYTES = int(os.getenv("MAX_FILE_SIZE_BYTES", str(100 * 1024 * 1024))) # 100 MB default
STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "s3")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "ciphernest-private-bhakti-2026-xyz739")
AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
S3_PREFIX = os.getenv("S3_PREFIX", "ciphernest-files/")
AWS_PROFILE = os.getenv("AWS_PROFILE") or None
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID") or None
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY") or None
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*")
PORT = int(os.getenv("PORT", "8000"))
HOST = os.getenv("HOST", "0.0.0.0")

# Initialize Cryptographic Service
try:
    cipher_service = CipherService(CIPHERNEST_ENCRYPTION_KEY)
    logger.info("CipherService initialized with 256-bit AES-GCM engine.")
except Exception as e:
    logger.critical(f"FATAL: Could not initialize CipherService: {e}")
    cipher_service = None

# Initialize Storage Backend
try:
    storage: BaseStorage = get_storage_backend(
        backend_type=STORAGE_BACKEND,
        bucket_name=S3_BUCKET_NAME,
        region=AWS_REGION,
        prefix=S3_PREFIX,
        profile_name=AWS_PROFILE,
        access_key_id=AWS_ACCESS_KEY_ID,
        secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    logger.info(f"Storage backend initialized: mode='{STORAGE_BACKEND}', bucket='{S3_BUCKET_NAME}'")
except Exception as e:
    logger.error(f"Error initializing storage backend: {e}")
    # Fallback to local storage for graceful diagnostics
    storage = get_storage_backend("local")

# Create FastAPI application
app = FastAPI(
    title="CipherNest API",
    description="Zero-Knowledge Encrypted Cloud Storage Engine",
    version="1.0.0",
)

# Configure CORS for decoupled frontend (e.g. S3 + CloudFront hosting)
origins = [o.strip() for o in ALLOWED_ORIGINS.split(",") if o.strip()]
if not origins:
    origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if "*" not in origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "Content-Length", "Content-Type"],
)

def sanitize_filename(filename: Optional[str]) -> str:
    """Sanitizes filename to prevent directory traversal and injection."""
    if not filename:
        return "unnamed_file.bin"
    base = os.path.basename(filename)
    import re
    cleaned = re.sub(r'[^a-zA-Z0-9_.\- ]', '_', base).strip()
    return cleaned or "unnamed_file.bin"


# --- API ENDPOINTS ---

@app.get("/api/health")
def health_check():
    """Returns system status, active cipher, and storage connectivity."""
    storage_health = storage.check_health() if storage else {"status": "uninitialized"}
    return {
        "status": "online",
        "app_name": "CipherNest",
        "version": "1.0.0",
        "cipher": "AES-256-GCM",
        "key_derivation": "HKDF-SHA256",
        "master_key_configured": cipher_service is not None,
        "chunk_size_bytes": CHUNK_SIZE_BYTES,
        "chunk_size_mb": round(CHUNK_SIZE_BYTES / (1024 * 1024), 2),
        "max_file_size_bytes": MAX_FILE_SIZE_BYTES,
        "max_file_size_mb": round(MAX_FILE_SIZE_BYTES / (1024 * 1024), 2),
        "storage": storage_health,
    }


@app.post("/api/files/upload")
def upload_file(file: UploadFile = File(...)):
    """
    Action 1: Upload File.
    - Validates file constraints.
    - Splits large files into manageable blocks.
    - Encrypts each block with AES-256-GCM and unique nonce + AAD.
    - Stores encrypted blocks and metadata manifest in the private S3 bucket.
    """
    if not cipher_service:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Encryption service is not configured. Please set CIPHERNEST_ENCRYPTION_KEY in .env.",
        )

    # 1. Validate file presence and filename
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file was provided for upload.",
        )

    safe_filename = sanitize_filename(file.filename)
    content_type = file.content_type or "application/octet-stream"

    # 2. Generate unique File ID and Cryptographic Salt
    file_id = str(uuid.uuid4())
    salt = cipher_service.generate_salt()
    salt_b64 = base64.b64encode(salt).decode("utf-8")

    # Derive unique per-file key
    file_key = cipher_service.derive_file_key(file_id, salt)

    # 3. Stream, split into blocks, and encrypt
    total_original_bytes = 0
    original_hasher = hashlib.sha256()
    chunks_metadata = []
    chunk_index = 0

    try:
        while True:
            # Read in chunk-sized blocks
            chunk_data = file.file.read(CHUNK_SIZE_BYTES)
            if not chunk_data:
                break

            total_original_bytes += len(chunk_data)

            # File size limit validation
            if total_original_bytes > MAX_FILE_SIZE_BYTES:
                # Clean up already uploaded chunks for this file
                try:
                    storage.delete_file(file_id)
                except Exception:
                    pass
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File exceeds maximum allowed size of {MAX_FILE_SIZE_BYTES // (1024*1024)} MB.",
                )

            # Update overall plaintext SHA-256 hash
            original_hasher.update(chunk_data)

            # Encrypt block with AES-256-GCM
            ciphertext, nonce, chunk_sha256 = cipher_service.encrypt_chunk(
                file_key=file_key,
                plaintext=chunk_data,
                chunk_index=chunk_index,
                file_id=file_id,
            )

            # Store encrypted block
            chunk_key = storage.put_chunk(file_id, chunk_index, ciphertext)

            chunks_metadata.append({
                "index": chunk_index,
                "chunk_key": chunk_key,
                "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
                "ciphertext_size": len(ciphertext),
                "ciphertext_sha256": chunk_sha256,
            })

            chunk_index += 1

        # Check for empty file
        if total_original_bytes == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Empty file (0 bytes) cannot be uploaded.",
            )

        # 4. Construct and store manifest
        uploaded_at = datetime.now(timezone.utc).isoformat()
        original_sha256 = original_hasher.hexdigest()

        manifest = {
            "file_id": file_id,
            "original_filename": safe_filename,
            "content_type": content_type,
            "original_size": total_original_bytes,
            "original_sha256": original_sha256,
            "chunk_size": CHUNK_SIZE_BYTES,
            "total_chunks": len(chunks_metadata),
            "salt_b64": salt_b64,
            "cipher": "AES-256-GCM",
            "uploaded_at": uploaded_at,
            "chunks": chunks_metadata,
        }

        storage.put_manifest(file_id, manifest)
        logger.info(
            f"Successfully encrypted and uploaded '{safe_filename}' "
            f"({total_original_bytes} bytes in {len(chunks_metadata)} blocks, id={file_id})"
        )

        return {
            "success": True,
            "message": "File encrypted and uploaded successfully.",
            "file": {
                "file_id": file_id,
                "original_filename": safe_filename,
                "content_type": content_type,
                "original_size": total_original_bytes,
                "total_chunks": len(chunks_metadata),
                "chunk_size": CHUNK_SIZE_BYTES,
                "uploaded_at": uploaded_at,
                "cipher": "AES-256-GCM",
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload failed for file '{safe_filename}': {e}", exc_info=True)
        # Clean up any partial blocks
        try:
            storage.delete_file(file_id)
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Upload & encryption failed: {str(e)}",
        )
    finally:
        try:
            file.file.close()
        except Exception:
            pass


@app.get("/api/files")
def list_files():
    """Lists all encrypted files currently stored in CipherNest."""
    try:
        files = storage.list_manifests()
        return {
            "success": True,
            "count": len(files),
            "files": files,
        }
    except Exception as e:
        logger.error(f"Failed to list files: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve files: {str(e)}",
        )


@app.get("/api/files/{file_id}/metadata")
def get_file_metadata(file_id: str):
    """Retrieves file metadata without leaking secret keys or nonces."""
    try:
        manifest = storage.get_manifest(file_id)
        return {
            "success": True,
            "file": {
                "file_id": manifest.get("file_id"),
                "original_filename": manifest.get("original_filename"),
                "content_type": manifest.get("content_type"),
                "original_size": manifest.get("original_size"),
                "total_chunks": manifest.get("total_chunks"),
                "chunk_size": manifest.get("chunk_size"),
                "cipher": manifest.get("cipher"),
                "uploaded_at": manifest.get("uploaded_at"),
            },
        }
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File with ID '{file_id}' was not found.",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


def stream_file_blocks(file_id: str, manifest: dict, cipher: CipherService, store: BaseStorage):
    """
    Generator yielding decrypted plaintext blocks for a given file.
    Verifies ciphertext SHA-256 and AES-256-GCM authentication tags on each block.
    """
    salt_b64 = manifest.get("salt_b64")
    if not salt_b64:
        raise ValueError("File manifest is corrupted (missing salt).")

    salt = base64.b64decode(salt_b64)
    file_key = cipher.derive_file_key(file_id, salt)

    chunks = manifest.get("chunks", [])
    chunks_sorted = sorted(chunks, key=lambda c: c.get("index", 0))

    for chunk_meta in chunks_sorted:
        chunk_idx = chunk_meta["index"]
        chunk_key = chunk_meta["chunk_key"]
        nonce_b64 = chunk_meta["nonce_b64"]
        expected_sha256 = chunk_meta.get("ciphertext_sha256")

        # 1. Fetch encrypted block from storage
        try:
            ciphertext = store.get_chunk(chunk_key)
        except Exception as read_err:
            logger.error(f"Failed to read block {chunk_idx} ({chunk_key}): {read_err}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to retrieve block {chunk_idx} from storage.",
            )

        # 2. Verify ciphertext checksum
        if expected_sha256:
            actual_sha256 = hashlib.sha256(ciphertext).hexdigest()
            if actual_sha256 != expected_sha256:
                raise TamperingDetectedError(
                    f"Checksum mismatch on block {chunk_idx}! Encrypted data was corrupted in storage."
                )

        # 3. Decrypt block
        nonce = base64.b64decode(nonce_b64)
        try:
            plaintext_block = cipher.decrypt_chunk(
                file_key=file_key,
                ciphertext=ciphertext,
                nonce=nonce,
                chunk_index=chunk_idx,
                file_id=file_id,
            )
        except TamperingDetectedError as t_err:
            logger.critical(f"TAMPERING DETECTED on block {chunk_idx} of {file_id}: {t_err}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Security alert: Block {chunk_idx} failed integrity verification.",
            )

        # 4. Yield plaintext block
        yield plaintext_block


@app.get("/api/files/{file_id}/download")
def download_file(file_id: str):
    """
    Action 2: Download File.
    - Retrieves encrypted blocks from S3.
    - Decrypts each block securely using AES-256-GCM.
    - Verifies block authentication tag and integrity.
    - Reconstructs and streams the original file to the browser.
    """
    if not cipher_service:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Encryption service is not configured.",
        )

    try:
        manifest = storage.get_manifest(file_id)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File '{file_id}' not found.",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Storage error while reading manifest: {str(e)}",
        )

    generator = stream_file_blocks(file_id, manifest, cipher_service, storage)

    original_filename = manifest.get("original_filename", f"{file_id}.bin")
    content_type = manifest.get("content_type", "application/octet-stream")
    original_size = manifest.get("original_size")

    # RFC 5987 / 6266 filename encoding for browser download compatibility
    encoded_filename = quote(original_filename)

    headers = {
        "Content-Disposition": f"attachment; filename=\"{original_filename}\"; filename*=UTF-8''{encoded_filename}",
        "Access-Control-Expose-Headers": "Content-Disposition, Content-Length, Content-Type",
    }
    if original_size:
        headers["Content-Length"] = str(original_size)

    return StreamingResponse(
        generator,
        media_type=content_type,
        headers=headers,
    )


@app.delete("/api/files/{file_id}")
def delete_file(file_id: str):
    """Deletes an encrypted file, all its stored blocks, and its manifest."""
    try:
        # Check if manifest exists
        try:
            storage.get_manifest(file_id)
        except FileNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"File '{file_id}' not found.",
            )

        storage.delete_file(file_id)
        logger.info(f"Purged file {file_id} from storage.")
        return {
            "success": True,
            "message": f"File '{file_id}' and all encrypted blocks were securely deleted.",
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete file {file_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete file: {str(e)}",
        )


# --- FRONTEND STATIC SERVING ---
# Allows running the full app locally with 'python app.py'
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.isdir(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    def serve_frontend_index():
        return FileResponse(os.path.join(frontend_dir, "index.html"))

    @app.get("/{filename:path}")
    def serve_static_root(filename: str):
        filepath = os.path.join(frontend_dir, filename)
        if os.path.isfile(filepath):
            return FileResponse(filepath)
        # Fallback to index.html for client-side routing
        return FileResponse(os.path.join(frontend_dir, "index.html"))


if __name__ == "__main__":
    print("=" * 64)
    print("Starting CipherNest Encrypted Cloud Storage Service...")
    print(f"Server URL:     http://localhost:{PORT}")
    print(f"Storage Mode:   {STORAGE_BACKEND}")
    print(f"Target Bucket:  {S3_BUCKET_NAME} ({AWS_REGION})")
    print(f"Encryption:     AES-256-GCM (HKDF-SHA256)")
    print("=" * 64)
    uvicorn.run("app:app", host=HOST, port=PORT, reload=True)
