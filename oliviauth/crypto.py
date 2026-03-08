"""
OliviaAuth Cryptography Module

Provides RSA-2048, AES-256-GCM, XOR obfuscation, and SSL certificate verification.
"""

import os
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import SSLVerificationError

# AES-GCM constants
AES_KEY_SIZE = 32  # 256 bits
AES_GCM_NONCE_SIZE = 12  # 96 bits (recommended for GCM)
RSA_KEY_SIZE = 2048


def generate_rsa_keypair():
    """
    Generate RSA-2048 key pair.

    Returns:
        tuple: (private_key, public_key) RSA key objects
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key) -> bytes:
    """
    Serialize RSA public key to PEM format.

    Args:
        public_key: RSA public key object

    Returns:
        bytes: PEM-encoded public key
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(pem_data: bytes):
    """
    Load RSA public key from PEM data.

    Args:
        pem_data: PEM-encoded public key bytes

    Returns:
        RSA public key object
    """
    return serialization.load_pem_public_key(pem_data)


def encrypt_aes_gcm(data: bytes, key: bytes) -> bytes:
    """
    Encrypt data using AES-256-GCM (authenticated encryption).

    Format: nonce (12 bytes) + ciphertext + tag (16 bytes)

    Args:
        data: Plaintext bytes to encrypt
        key: 256-bit AES key

    Returns:
        bytes: nonce + ciphertext + authentication tag
    """
    nonce = os.urandom(AES_GCM_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_aes_gcm(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypt data encrypted with AES-256-GCM.

    Args:
        encrypted_data: nonce + ciphertext + tag
        key: 256-bit AES key

    Returns:
        bytes: Decrypted plaintext

    Raises:
        InvalidTag: If authentication fails (data was tampered)
    """
    nonce = encrypted_data[:AES_GCM_NONCE_SIZE]
    ciphertext = encrypted_data[AES_GCM_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_with_rsa(data: bytes, public_key) -> bytes:
    """
    Encrypt data using RSA-OAEP with SHA-256.

    Args:
        data: Data to encrypt (typically an AES key)
        public_key: RSA public key object

    Returns:
        bytes: RSA-encrypted data (256 bytes for RSA-2048)
    """
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_with_rsa(encrypted_data: bytes, private_key) -> bytes:
    """
    Decrypt data encrypted with RSA-OAEP.

    Args:
        encrypted_data: RSA-encrypted data
        private_key: RSA private key object

    Returns:
        bytes: Decrypted data
    """
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def xor_obfuscate(data: str, key: str) -> str:
    """
    Obfuscate string using XOR with repeating key.

    Args:
        data: String to obfuscate
        key: Obfuscation key

    Returns:
        str: URL-safe Base64 encoded obfuscated data
    """
    data_bytes = data.encode('utf-8')
    key_bytes = key.encode('utf-8')
    obfuscated = bytearray()
    for i, b in enumerate(data_bytes):
        obfuscated.append(b ^ key_bytes[i % len(key_bytes)])
    return base64.urlsafe_b64encode(obfuscated).decode('utf-8')


def xor_deobfuscate(data: str, key: str) -> str:
    """
    Reverse XOR obfuscation.

    Args:
        data: URL-safe Base64 encoded obfuscated string
        key: Obfuscation key

    Returns:
        str: Original string
    """
    obf_bytes = base64.urlsafe_b64decode(data)
    key_bytes = key.encode('utf-8')
    deobfuscated = bytearray()
    for i, b in enumerate(obf_bytes):
        deobfuscated.append(b ^ key_bytes[i % len(key_bytes)])
    return deobfuscated.decode('utf-8')


def generate_aes_key() -> bytes:
    """
    Generate random 256-bit AES key.

    Returns:
        bytes: 32-byte random key
    """
    return os.urandom(AES_KEY_SIZE)


# =============================================================================
# SSL Certificate Verification
#
# DESIGN: Em vez de abrir uma conexão TCP/TLS extra só para checar o cert
# (o que causava múltiplos handshakes TLS detectados pelo GFW como suspeito),
# extraímos o certificado da própria conexão HTTP que já acontece em
# _create_session(). Zero conexões extras.
# =============================================================================

def extract_cert_sha256_from_url(url: str, timeout: int = 10) -> str:
    """
    Faz um HEAD request leve ao servidor e extrai o SHA256 do certificado
    SSL da conexão, sem enviar/receber dados desnecessários.

    Usa stream=True para manter o socket aberto e acessar o cert via
    o caminho interno do urllib3 (response.raw._fp.fp.raw).

    Args:
        url: URL HTTPS do servidor

    Returns:
        str: SHA256 hex lowercase do certificado DER, ou "" se não disponível
    """
    import requests as _requests
    try:
        resp = _requests.head(url, timeout=timeout, stream=True)
        try:
            sock = None
            raw = resp.raw

            # Path 1: urllib3 exposes _connection.sock (SSLSocket)
            conn = getattr(raw, '_connection', None)
            if conn:
                sock = getattr(conn, 'sock', None)

            # Path 2: fallback via _fp chain
            if not sock or not hasattr(sock, 'getpeercert'):
                if hasattr(raw, '_fp') and hasattr(raw._fp, 'fp'):
                    fp = raw._fp.fp
                    sock = getattr(fp, 'raw', None) or getattr(fp, '_sock', None)

            if sock and hasattr(sock, 'getpeercert'):
                cert_der = sock.getpeercert(binary_form=True)
                if cert_der:
                    return hashlib.sha256(cert_der).hexdigest().lower()
        finally:
            resp.close()
    except Exception:
        pass
    return ""


def verify_cert_sha256(actual_sha256: str, expected_sha256: str) -> bool:
    """
    Compara o SHA256 real do certificado com o valor esperado configurado
    pelo desenvolvedor (ssl_sha256). Levanta SSLVerificationError se não bater.

    Esta função é chamada APÓS a request de sessão, usando o cert extraído
    da própria conexão — sem abrir socket adicional.

    Args:
        actual_sha256: SHA256 extraído via extract_cert_sha256_from_response()
        expected_sha256: SHA256 configurado no construtor do Olivia (ssl_sha256)

    Returns:
        True se OK ou se pinning não está configurado

    Raises:
        SSLVerificationError: se os hashes não batem (possível servidor pirata)
    """
    import logging
    logger = logging.getLogger("oliviauth")

    if not expected_sha256:
        return True  # SSL pinning não configurado, sem verificação

    if not actual_sha256:
        # Não conseguiu extrair o cert da conexão (HTTP puro, socket fechado,
        # ou versão de urllib3 incompatível). Não bloqueia — só avisa.
        logger.warning(
            "ssl_sha256 está configurado mas não foi possível extrair o "
            "certificado da conexão para verificar o pinning. "
            "Verificação de SSL pulada."
        )
        return True

    expected_clean = expected_sha256.lower().replace(':', '').replace(' ', '')

    if actual_sha256 != expected_clean:
        raise SSLVerificationError(
            f"SSL certificate mismatch! Possible pirated server detected.\n"
            f"Expected: {expected_clean}\n"
            f"Got:      {actual_sha256}\n"
            f"Do not enter your license key on this server!"
        )

    logger.debug("SSL certificate pinning verified successfully")
    return True
