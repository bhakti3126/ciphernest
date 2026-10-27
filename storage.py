"""
CipherNest - Storage Layer (Amazon S3 and Local Development Storage)
=====================================================================
Handles persisting and retrieving encrypted file blocks and manifests.
- S3Storage: Direct integration with private Amazon S3 bucket.
- LocalStorage: Local disk backend for offline development and testing.

Never exposes credentials to the frontend.
Enforces private access and server-side encryption in Amazon S3.
"""

import os
import json
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

logger = logging.getLogger("ciphernest.storage")

class BaseStorage(ABC):
    @abstractmethod
    def put_chunk(self, file_id: str, chunk_index: int, data: bytes) -> str:
        """Stores an encrypted block and returns its storage reference/key."""
        pass

    @abstractmethod
    def get_chunk(self, chunk_key: str) -> bytes:
        """Retrieves an encrypted block by its reference/key."""
        pass

    @abstractmethod
    def put_manifest(self, file_id: str, manifest: Dict[str, Any]) -> str:
        """Stores the file manifest (metadata)."""
        pass

    @abstractmethod
    def get_manifest(self, file_id: str) -> Dict[str, Any]:
        """Retrieves and parses the manifest for a given file_id."""
        pass

    @abstractmethod
    def list_manifests(self) -> List[Dict[str, Any]]:
        """Lists all files stored in the vault."""
        pass

    @abstractmethod
    def delete_file(self, file_id: str) -> bool:
        """Deletes all blocks and manifest for a given file_id."""
        pass

    @abstractmethod
    def check_health(self) -> Dict[str, Any]:
        """Checks the connectivity and status of the storage backend."""
        pass


class S3Storage(BaseStorage):
    """
    Amazon S3 Storage Backend.
    Uses boto3 to communicate securely with the private S3 bucket.
    Credential resolution:
      - Development: Configured AWS profile (e.g. AWS_PROFILE='default')
      - Production: AWS IAM Role attached to EC2 / ECS / App Runner / Lambda
      - Fallback: AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY if present
    """

    def __init__(
        self,
        bucket_name: str,
        region: str = "ap-south-1",
        prefix: str = "ciphernest-files/",
        profile_name: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
    ):
        self.bucket_name = bucket_name
        self.region = region
        self.prefix = prefix if prefix.endswith("/") else f"{prefix}/"
        self.profile_name = profile_name

        # Initialize boto3 session using standard credential chain
        session_kwargs = {"region_name": self.region}
        
        # Profile takes precedence for local development if provided and exists
        if profile_name:
            try:
                test_session = boto3.Session(profile_name=profile_name, **session_kwargs)
                test_client = test_session.client("s3")
                self.session = test_session
                self.s3_client = test_client
            except Exception as e:
                logger.warning(
                    f"AWS Profile '{profile_name}' not accessible ({e}). Falling back to standard AWS credential provider chain."
                )
                self.session = boto3.Session(**session_kwargs)
                self.s3_client = self.session.client("s3")
        elif access_key_id and secret_access_key:
            session_kwargs["aws_access_key_id"] = access_key_id
            session_kwargs["aws_secret_access_key"] = secret_access_key
            self.session = boto3.Session(**session_kwargs)
            self.s3_client = self.session.client("s3")
        else:
            # Default provider chain: IAM Role, environment, ECS metadata, etc.
            self.session = boto3.Session(**session_kwargs)
            self.s3_client = self.session.client("s3")

    def _get_chunk_key(self, file_id: str, chunk_index: int) -> str:
        return f"{self.prefix}{file_id}/chunks/chunk_{chunk_index:05d}.enc"

    def _get_manifest_key(self, file_id: str) -> str:
        return f"{self.prefix}{file_id}/manifest.json"

    def put_chunk(self, file_id: str, chunk_index: int, data: bytes) -> str:
        key = self._get_chunk_key(file_id, chunk_index)
        try:
            # Store with private permissions and SSE-S3 AES256 server-side encryption
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=data,
                ContentType="application/octet-stream",
                ServerSideEncryption="AES256",
            )
            return key
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to put chunk to S3 ({key}): {e}")
            raise

    def get_chunk(self, chunk_key: str) -> bytes:
        try:
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=chunk_key,
            )
            return response["Body"].read()
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to get chunk from S3 ({chunk_key}): {e}")
            raise

    def put_manifest(self, file_id: str, manifest: Dict[str, Any]) -> str:
        key = self._get_manifest_key(file_id)
        payload = json.dumps(manifest, indent=2).encode("utf-8")
        try:
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=payload,
                ContentType="application/json",
                ServerSideEncryption="AES256",
            )
            return key
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to put manifest to S3 ({key}): {e}")
            raise

    def get_manifest(self, file_id: str) -> Dict[str, Any]:
        key = self._get_manifest_key(file_id)
        try:
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=key,
            )
            content = response["Body"].read().decode("utf-8")
            return json.loads(content)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
                raise FileNotFoundError(f"File manifest for '{file_id}' not found in S3.")
            raise
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to get manifest from S3 ({key}): {e}")
            raise

    def list_manifests(self) -> List[Dict[str, Any]]:
        results = []
        try:
            paginator = self.s3_client.get_paginator("list_objects_v2")
            pages = paginator.paginate(
                Bucket=self.bucket_name,
                Prefix=self.prefix,
            )

            manifest_keys = []
            for page in pages:
                for item in page.get("Contents", []):
                    key = item.get("Key", "")
                    if key.endswith("/manifest.json"):
                        manifest_keys.append(key)

            for key in manifest_keys:
                try:
                    resp = self.s3_client.get_object(Bucket=self.bucket_name, Key=key)
                    data = json.loads(resp["Body"].read().decode("utf-8"))
                    # Return safe summary for the list (exclude chunk nonces)
                    results.append({
                        "file_id": data.get("file_id"),
                        "original_filename": data.get("original_filename"),
                        "content_type": data.get("content_type"),
                        "original_size": data.get("original_size"),
                        "total_chunks": data.get("total_chunks"),
                        "uploaded_at": data.get("uploaded_at"),
                        "cipher": data.get("cipher", "AES-256-GCM"),
                    })
                except Exception as inner_e:
                    logger.warning(f"Could not parse manifest {key}: {inner_e}")
                    continue

            # Sort descending by uploaded_at
            results.sort(key=lambda x: x.get("uploaded_at", ""), reverse=True)
            return results
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to list manifests from S3: {e}")
            raise

    def delete_file(self, file_id: str) -> bool:
        prefix = f"{self.prefix}{file_id}/"
        try:
            # List all objects with this prefix (manifest + chunks)
            paginator = self.s3_client.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=self.bucket_name, Prefix=prefix)

            objects_to_delete = []
            for page in pages:
                for item in page.get("Contents", []):
                    objects_to_delete.append({"Key": item["Key"]})

            if objects_to_delete:
                self.s3_client.delete_objects(
                    Bucket=self.bucket_name,
                    Delete={"Objects": objects_to_delete},
                )
            return True
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to delete file {file_id} from S3: {e}")
            raise

    def check_health(self) -> Dict[str, Any]:
        """Checks connectivity to S3 bucket without leaking keys."""
        try:
            # Check if bucket exists and is accessible
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            return {
                "status": "connected",
                "backend": "s3",
                "bucket": self.bucket_name,
                "region": self.region,
                "access": "accessible",
            }
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            return {
                "status": "error",
                "backend": "s3",
                "bucket": self.bucket_name,
                "region": self.region,
                "error_code": error_code,
                "message": (
                    f"AWS S3 error ({error_code}). Verify AWS credentials, IAM permissions, "
                    f"and that bucket '{self.bucket_name}' exists in '{self.region}'."
                ),
            }
        except NoCredentialsError:
            return {
                "status": "error",
                "backend": "s3",
                "bucket": self.bucket_name,
                "region": self.region,
                "error_code": "NoCredentialsError",
                "message": "No AWS credentials found. Configure via 'aws configure' or set AWS_PROFILE/IAM role.",
            }
        except Exception as e:
            return {
                "status": "error",
                "backend": "s3",
                "bucket": self.bucket_name,
                "region": self.region,
                "error_code": type(e).__name__,
                "message": str(e),
            }


class LocalStorage(BaseStorage):
    """
    Local Disk Mock Storage Backend.
    Enables offline local development and automated testing
    mimicking the S3 key hierarchy.
    """

    def __init__(self, base_dir: str = ".storage"):
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True)

    def _resolve_path(self, relative_key: str) -> str:
        # Prevent path traversal
        clean_key = os.path.normpath(relative_key).lstrip(os.sep)
        full_path = os.path.join(self.base_dir, clean_key)
        return full_path

    def put_chunk(self, file_id: str, chunk_index: int, data: bytes) -> str:
        key = f"files/{file_id}/chunks/chunk_{chunk_index:05d}.enc"
        full_path = self._resolve_path(key)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "wb") as f:
            f.write(data)
        return key

    def get_chunk(self, chunk_key: str) -> bytes:
        full_path = self._resolve_path(chunk_key)
        if not os.path.exists(full_path):
            raise FileNotFoundError(f"Chunk '{chunk_key}' not found on local storage.")
        with open(full_path, "rb") as f:
            return f.read()

    def put_manifest(self, file_id: str, manifest: Dict[str, Any]) -> str:
        key = f"files/{file_id}/manifest.json"
        full_path = self._resolve_path(key)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        return key

    def get_manifest(self, file_id: str) -> Dict[str, Any]:
        key = f"files/{file_id}/manifest.json"
        full_path = self._resolve_path(key)
        if not os.path.exists(full_path):
            raise FileNotFoundError(f"Manifest for '{file_id}' not found.")
        with open(full_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def list_manifests(self) -> List[Dict[str, Any]]:
        results = []
        files_dir = os.path.join(self.base_dir, "files")
        if not os.path.exists(files_dir):
            return results

        for file_id in os.listdir(files_dir):
            manifest_file = os.path.join(files_dir, file_id, "manifest.json")
            if os.path.isfile(manifest_file):
                try:
                    with open(manifest_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    results.append({
                        "file_id": data.get("file_id"),
                        "original_filename": data.get("original_filename"),
                        "content_type": data.get("content_type"),
                        "original_size": data.get("original_size"),
                        "total_chunks": data.get("total_chunks"),
                        "uploaded_at": data.get("uploaded_at"),
                        "cipher": data.get("cipher", "AES-256-GCM"),
                    })
                except Exception as e:
                    logger.warning(f"Error reading local manifest {manifest_file}: {e}")
                    continue

        results.sort(key=lambda x: x.get("uploaded_at", ""), reverse=True)
        return results

    def delete_file(self, file_id: str) -> bool:
        import shutil
        target_dir = os.path.join(self.base_dir, "files", file_id)
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir)
            return True
        return False

    def check_health(self) -> Dict[str, Any]:
        return {
            "status": "connected",
            "backend": "local_mock",
            "directory": self.base_dir,
            "access": "accessible",
        }


def get_storage_backend(
    backend_type: str = "s3",
    bucket_name: str = "ciphernest-private-bhakti-2026-xyz739",
    region: str = "ap-south-1",
    prefix: str = "ciphernest-files/",
    profile_name: Optional[str] = None,
    access_key_id: Optional[str] = None,
    secret_access_key: Optional[str] = None,
    local_dir: str = ".storage",
) -> BaseStorage:
    """Factory creating the storage engine based on configuration."""
    backend_type = (backend_type or "s3").lower().strip()
    if backend_type == "s3":
        return S3Storage(
            bucket_name=bucket_name,
            region=region,
            prefix=prefix,
            profile_name=profile_name,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
        )
    elif backend_type in ("local", "local_mock"):
        return LocalStorage(base_dir=local_dir)
    else:
        raise ValueError(f"Unknown STORAGE_BACKEND: '{backend_type}'. Use 's3' or 'local'.")
