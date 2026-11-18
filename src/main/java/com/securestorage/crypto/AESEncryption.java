package com.securestorage.crypto;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Arrays;

/**
 * AES-256-GCM Encryption / Decryption
 *
 * Why AES-256-GCM?
 * ┌──────────────────────────────────────────────────────────────────┐
 * │ Property          │ AES-256-CBC      │ AES-256-GCM (chosen)     │
 * ├──────────────────────────────────────────────────────────────────┤
 * │ Confidentiality   │ ✓ Yes            │ ✓ Yes                    │
 * │ Integrity         │ ✗ No (need HMAC) │ ✓ Built-in (auth tag)    │
 * │ Authentication    │ ✗ No             │ ✓ Built-in               │
 * │ Padding attacks   │ Vulnerable (PKCS)│ No padding needed        │
 * │ Parallelizable    │ ✗ Decrypt only   │ ✓ Both directions        │
 * └──────────────────────────────────────────────────────────────────┘
 *
 * GCM provides Authenticated Encryption with Associated Data (AEAD):
 * - If anyone tampers with the ciphertext, decryption throws AEADBadTagException
 * - This replaces the need for a separate HMAC integrity check
 *
 * Output wire format: [ IV (12 bytes) ][ ciphertext + auth tag (variable) ]
 * The 12-byte IV is randomly generated per operation (never reused).
 */
public class AESEncryption {

    private static final String ALGORITHM      = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int    KEY_SIZE_BITS  = 256;
    private static final int    IV_LENGTH      = 12;   // 96-bit IV: GCM standard
    private static final int    TAG_BITS       = 128;  // 16-byte authentication tag

    private final SecureRandom secureRandom = new SecureRandom();

    // ══════════════════════ Key Generation ═══════════════════════

    /**
     * Generates a new cryptographically random AES-256 key.
     *
     * @return A fresh SecretKey suitable for AES-256-GCM
     * @throws NoSuchAlgorithmException if AES is not available (won't happen on standard JDK)
     */
    public SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE_BITS, secureRandom);
        return keyGen.generateKey();
    }

    /**
     * Reconstructs an AES SecretKey from raw key bytes.
     * Used after RSA-decrypting the wrapped AES key.
     *
     * @param keyBytes 32 bytes (256-bit)
     * @return SecretKey for AES operations
     */
    public SecretKey keyFromBytes(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    // ══════════════════════ Encryption ═══════════════════════════

    /**
     * Encrypts plaintext using AES-256-GCM.
     *
     * A fresh random IV is generated for every call — IV reuse with the same
     * key is catastrophic in GCM mode (breaks both confidentiality and integrity).
     *
     * @param plaintext Bytes to encrypt
     * @param key       AES-256 secret key
     * @return          Encrypted bytes: [ IV (12) | ciphertext+tag (variable) ]
     * @throws Exception on cipher initialization or encryption failure
     */
    public byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception {
        // Generate a fresh random IV for each encryption
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);

        // Initialize GCM cipher
        Cipher          cipher    = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec paramSpec = new GCMParameterSpec(TAG_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

        // Encrypt — GCM appends the 16-byte auth tag to the ciphertext
        byte[] ciphertextWithTag = cipher.doFinal(plaintext);

        // Prepend IV so decryptor can extract it
        byte[] result = new byte[IV_LENGTH + ciphertextWithTag.length];
        System.arraycopy(iv,              0, result, 0,         IV_LENGTH);
        System.arraycopy(ciphertextWithTag, 0, result, IV_LENGTH, ciphertextWithTag.length);

        return result;
    }

    // ══════════════════════ Decryption ═══════════════════════════

    /**
     * Decrypts AES-256-GCM encrypted data.
     *
     * The GCM authentication tag is verified automatically by the cipher.
     * If the ciphertext was tampered with, an AEADBadTagException is thrown
     * before any plaintext bytes are returned — this prevents partial decryption
     * of corrupted data.
     *
     * @param encryptedData Bytes in format: [ IV (12) | ciphertext+tag ]
     * @param key           AES-256 secret key
     * @return              Decrypted plaintext bytes
     * @throws AEADBadTagException      if ciphertext was tampered with (integrity failure)
     * @throws IllegalArgumentException if input is malformed (too short)
     * @throws Exception                on cipher failure
     */
    public byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        // Minimum valid size: 12-byte IV + 16-byte tag = 28 bytes
        if (encryptedData == null || encryptedData.length < IV_LENGTH + 16) {
            throw new IllegalArgumentException(
                "Encrypted data is too short to be valid AES-GCM output");
        }

        // Extract IV from the front
        byte[] iv         = Arrays.copyOfRange(encryptedData, 0, IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, IV_LENGTH, encryptedData.length);

        // Initialize GCM cipher for decryption
        Cipher           cipher    = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec paramSpec = new GCMParameterSpec(TAG_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

        // Decrypt AND verify authentication tag in one step
        // Throws javax.crypto.AEADBadTagException if authentication fails
        return cipher.doFinal(ciphertext);
    }
}
