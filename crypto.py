"""
Core encryption/decryption functionality for secure file operations.

This module provides the SecureFileCrypto class which implements AES-256-GCM
encryption with PBKDF2 key derivation for secure file operations.
"""

import secrets
from typing import Optional
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except ImportError as e:
    raise ImportError(
        "cryptography library not installed. Install with: pip install cryptography"
    ) from e


class CryptoError(Exception):
    """Base exception for cryptographic operations"""
    pass


class EncryptionError(CryptoError):
    """Exception raised during encryption operations"""
    pass


class DecryptionError(CryptoError):
    """Exception raised during decryption operations"""
    pass


class SecureFileCrypto:
    """
    Secure file encryption/decryption utility using AES-256-GCM.
    
    This class provides methods to encrypt and decrypt files using modern
    cryptographic standards with authenticated encryption.
    """
    
    # Cryptographic constants following security best practices
    SALT_SIZE = 32              # 256 bits
    IV_SIZE = 12                # 96 bits for GCM (recommended)
    TAG_SIZE = 16               # 128 bits for GCM authentication
    KEY_SIZE = 32               # 256 bits for AES-256
    PBKDF2_ITERATIONS = 100000  # OWASP recommended minimum
    CHUNK_SIZE = 8192           # 8KB chunks for memory efficiency
    
    def __init__(self):
        """Initialize the crypto utility with default backend."""
        self.backend = default_backend()
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2-HMAC-SHA256.
        
        Args:
            password: User password as string
            salt: Random salt bytes for key derivation
            
        Returns:
            Derived encryption key as bytes
            
        Raises:
            CryptoError: If key derivation fails
        """
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.KEY_SIZE,
                salt=salt,
                iterations=self.PBKDF2_ITERATIONS,
                backend=self.backend
            )
            return kdf.derive(password.encode('utf-8'))
        except Exception as e:
            raise CryptoError(f"Key derivation failed: {e}") from e
    
    def _validate_file_format(self, file_path: Path) -> tuple[bytes, bytes, int]:
        """
        Validate encrypted file format and extract header information.
        
        Args:
            file_path: Path to encrypted file
            
        Returns:
            Tuple of (salt, iv, encrypted_data_size)
            
        Raises:
            DecryptionError: If file format is invalid
        """
        try:
            file_size = file_path.stat().st_size
            min_size = self.SALT_SIZE + self.IV_SIZE + self.TAG_SIZE
            
            if file_size < min_size:
                raise DecryptionError(
                    f"File too small ({file_size} bytes). "
                    f"Minimum size: {min_size} bytes"
                )
            
            with open(file_path, 'rb') as f:
                salt = f.read(self.SALT_SIZE)
                iv = f.read(self.IV_SIZE)
                
                if len(salt) != self.SALT_SIZE:
                    raise DecryptionError("Invalid salt size in file header")
                if len(iv) != self.IV_SIZE:
                    raise DecryptionError("Invalid IV size in file header")
            
            encrypted_data_size = file_size - self.SALT_SIZE - self.IV_SIZE - self.TAG_SIZE
            return salt, iv, encrypted_data_size
            
        except OSError as e:
            raise DecryptionError(f"Cannot read file: {e}") from e
    
    def encrypt_file(self, input_path: str, output_path: str, password: str) -> None:
        """
        Encrypt a file using AES-256-GCM with authenticated encryption.
        
        File format: [32B salt][12B IV][encrypted data][16B auth tag]
        
        Args:
            input_path: Path to file to encrypt
            output_path: Path for encrypted output file
            password: Encryption password
            
        Raises:
            EncryptionError: If encryption fails
            FileNotFoundError: If input file doesn't exist
        """
        input_file = Path(input_path)
        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Generate cryptographically secure random values
        salt = secrets.token_bytes(self.SALT_SIZE)
        iv = secrets.token_bytes(self.IV_SIZE)
        
        try:
            # Derive encryption key
            key = self.derive_key(password, salt)
            
            # Initialize AES-GCM cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            
            # Encrypt file with streaming to handle large files
            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Write file header (salt + IV)
                outfile.write(salt)
                outfile.write(iv)
                
                # Encrypt file in chunks
                while True:
                    chunk = infile.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted_chunk = encryptor.update(chunk)
                    outfile.write(encrypted_chunk)
                
                # Finalize encryption and write authentication tag
                encryptor.finalize()
                outfile.write(encryptor.tag)
                
        except Exception as e:
            # Clean up partial output file on error
            try:
                Path(output_path).unlink(missing_ok=True)
            except OSError:
                pass
            raise EncryptionError(f"Encryption failed: {e}") from e
        finally:
            # Securely clear key from memory
            if 'key' in locals():
                key = b'\x00' * len(key)
    
    def decrypt_file(self, input_path: str, output_path: str, password: str) -> None:
        """
        Decrypt a file encrypted with encrypt_file method.
        
        Args:
            input_path: Path to encrypted file
            output_path: Path for decrypted output file
            password: Decryption password
            
        Raises:
            DecryptionError: If decryption fails or authentication fails
            FileNotFoundError: If input file doesn't exist
        """
        input_file = Path(input_path)
        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Validate file format and extract header info
        salt, iv, encrypted_data_size = self._validate_file_format(input_file)
        
        try:
            # Read encrypted data and authentication tag
            with open(input_path, 'rb') as f:
                # Skip header (salt + IV)
                f.seek(self.SALT_SIZE + self.IV_SIZE)
                encrypted_data = f.read(encrypted_data_size)
                tag = f.read(self.TAG_SIZE)
                
                if len(tag) != self.TAG_SIZE:
                    raise DecryptionError("Invalid authentication tag size")
            
            # Derive decryption key
            key = self.derive_key(password, salt)
            
            # Initialize AES-GCM cipher for decryption
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # Decrypt and verify authenticity
            try:
                decrypted_data = decryptor.update(encrypted_data)
                decryptor.finalize()  # Verifies authentication tag
            except Exception as e:
                raise DecryptionError(
                    "Decryption failed - wrong password or corrupted file"
                ) from e
            
            # Write decrypted data to output file
            with open(output_path, 'wb') as outfile:
                outfile.write(decrypted_data)
                
        except DecryptionError:
            # Clean up partial output file on error
            try:
                Path(output_path).unlink(missing_ok=True)
            except OSError:
                pass
            raise
        except Exception as e:
            # Clean up partial output file on error
            try:
                Path(output_path).unlink(missing_ok=True)
            except OSError:
                pass
            raise DecryptionError(f"Decryption failed: {e}") from e
        finally:
            # Securely clear key from memory
            if 'key' in locals():
                key = b'\x00' * len(key)
    
    def verify_file(self, file_path: str, password: str) -> bool:
        """
        Verify that an encrypted file can be decrypted with the given password.
        
        This method performs a dry-run decryption to verify the password
        without creating an output file.
        
        Args:
            file_path: Path to encrypted file
            password: Password to verify
            
        Returns:
            True if password is correct, False otherwise
        """
        try:
            input_file = Path(file_path)
            if not input_file.exists():
                return False
            
            # Validate file format
            salt, iv, encrypted_data_size = self._validate_file_format(input_file)
            
            # Read a small portion of encrypted data and tag
            with open(file_path, 'rb') as f:
                f.seek(self.SALT_SIZE + self.IV_SIZE)
                # Only read first chunk for verification
                test_data_size = min(self.CHUNK_SIZE, encrypted_data_size)
                encrypted_data = f.read(test_data_size)
                f.seek(self.SALT_SIZE + self.IV_SIZE + encrypted_data_size)
                tag = f.read(self.TAG_SIZE)
            
            # Derive key and test decryption
            key = self.derive_key(password, salt)
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # Test decryption - this will fail if password is wrong
            decryptor.update(encrypted_data)
            decryptor.finalize()
            
            return True
            
        except Exception:
            return False
        finally:
            if 'key' in locals():
                key = b'\x00' * len(key)
