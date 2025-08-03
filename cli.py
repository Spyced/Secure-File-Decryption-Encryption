"""
Command-line interface for the secure file encryption utility.

This module provides the CLI functionality including argument parsing,
user interaction, and operation dispatch.
"""

import sys
import getpass
from pathlib import Path
from typing import Optional

from .crypto import SecureFileCrypto, CryptoError, EncryptionError, DecryptionError


class CLIError(Exception):
    """Exception for CLI-specific errors"""
    pass


def get_secure_password(prompt: str, confirm: bool = False) -> str:
    """
    Get password from user with secure input (no echo).
    
    Args:
        prompt: Password prompt message
        confirm: Whether to ask for password confirmation
        
    Returns:
        User password
        
    Raises:
        CLIError: If passwords don't match or input is cancelled
    """
    try:
        password = getpass.getpass(prompt)
        
        if not password:
            raise CLIError("Password cannot be empty")
        
        if confirm:
            confirm_password = getpass.getpass("Confirm password: ")
            if password != confirm_password:
                raise CLIError("Passwords do not match")
        
        return password
        
    except KeyboardInterrupt:
        raise CLIError("Operation cancelled by user")


def confirm_overwrite(file_path: str) -> bool:
    """
    Ask user confirmation before overwriting existing file.
    
    Args:
        file_path: Path to potentially existing file
        
    Returns:
        True if user confirms overwrite, False otherwise
    """
    if Path(file_path).exists():
        try:
            response = input(f"File '{file_path}' already exists. Overwrite? (y/N): ")
            return response.lower() in ['y', 'yes']
        except KeyboardInterrupt:
            return False
    return True


def print_usage():
    """Print usage instructions"""
    print("=== Secure File Encryption/Decryption Utility ===")
    print("Uses AES-256-GCM with PBKDF2 key derivation")
    print()
    print("Usage:")
    print("  Encrypt: python -m secure_crypto encrypt <input_file> <output_file>")
    print("  Decrypt: python -m secure_crypto decrypt <input_file> <output_file>")
    print("  Verify:  python -m secure_crypto verify <encrypted_file>")
    print()
    print("Examples:")
    print("  python -m secure_crypto encrypt document.txt document.txt.enc")
    print("  python -m secure_crypto decrypt document.txt.enc document_decrypted.txt")
    print("  python -m secure_crypto verify document.txt.enc")


def handle_encrypt(input_file: str, output_file: str) -> int:
    """
    Handle file encryption operation.
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Check if output file exists and get confirmation
        if not confirm_overwrite(output_file):
            print("Operation cancelled")
            return 1
        
        # Get password with confirmation
        password = get_secure_password("Enter encryption password: ", confirm=True)
        
        # Perform encryption
        crypto = SecureFileCrypto()
        crypto.encrypt_file(input_file, output_file, password)
        
        print(f"✓ File encrypted successfully: {output_file}")
        return 0
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return 1
    except EncryptionError as e:
        print(f"Encryption error: {e}")
        return 1
    except CLIError as e:
        print(f"Error: {e}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


def handle_decrypt(input_file: str, output_file: str) -> int:
    """
    Handle file decryption operation.
    
    Args:
        input_file: Path to encrypted file
        output_file: Path to output file
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Check if output file exists and get confirmation
        if not confirm_overwrite(output_file):
            print("Operation cancelled")
            return 1
        
        # Get password
        password = get_secure_password("Enter decryption password: ")
        
        # Perform decryption
        crypto = SecureFileCrypto()
        crypto.decrypt_file(input_file, output_file, password)
        
        print(f"✓ File decrypted successfully: {output_file}")
        return 0
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return 1
    except DecryptionError as e:
        print(f"Decryption error: {e}")
        return 1
    except CLIError as e:
        print(f"Error: {e}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


def handle_verify(input_file: str) -> int:
    """
    Handle file verification operation.
    
    Args:
        input_file: Path to encrypted file
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Get password
        password = get_secure_password("Enter password to verify: ")
        
        # Perform verification
        crypto = SecureFileCrypto()
        is_valid = crypto.verify_file(input_file, password)
        
        if is_valid:
            print("✓ Password is correct - file can be decrypted")
            return 0
        else:
            print("✗ Password is incorrect or file is corrupted")
            return 1
            
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return 1
    except CLIError as e:
        print(f"Error: {e}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


def main() -> int:
    """
    Main CLI entry point.
    
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    # Parse command line arguments
    if len(sys.argv) < 2:
        print_usage()
        return 1
    
    operation = sys.argv[1].lower()
    
    # Handle different operations
    if operation == 'encrypt':
        if len(sys.argv) != 4:
            print("Error: encrypt requires input and output file paths")
            print("Usage: python -m secure_crypto encrypt <input_file> <output_file>")
            return 1
        return handle_encrypt(sys.argv[2], sys.argv[3])
    
    elif operation == 'decrypt':
        if len(sys.argv) != 4:
            print("Error: decrypt requires input and output file paths")
            print("Usage: python -m secure_crypto decrypt <input_file> <output_file>")
            return 1
        return handle_decrypt(sys.argv[2], sys.argv[3])
    
    elif operation == 'verify':
        if len(sys.argv) != 3:
            print("Error: verify requires encrypted file path")
            print("Usage: python -m secure_crypto verify <encrypted_file>")
            return 1
        return handle_verify(sys.argv[2])
    
    elif operation in ['-h', '--help', 'help']:
        print_usage()
        return 0
    
    else:
        print(f"Error: Unknown operation '{operation}'")
        print("Valid operations: encrypt, decrypt, verify")
        print("Use 'help' for usage instructions")
        return 1


if __name__ == "__main__":
    sys.exit(main())
