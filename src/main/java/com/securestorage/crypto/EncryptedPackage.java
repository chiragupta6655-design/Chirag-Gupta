package com.securestorage.crypto;

import java.io.Serializable;

/**
 * Immutable container for a hybrid-encrypted file.
 *
 * Contains two distinct encrypted components:
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  EncryptedPackage                                               │
 * │  ┌────────────────────────────────────────────────────────┐     │
 * │  │ encryptedAesKey (256 bytes)                            │     │
 * │  │  └─ AES-256 key, wrapped with RSA-2048-OAEP           │     │
 * │  │     Only decryptable by the matching RSA private key   │     │
 * │  ├────────────────────────────────────────────────────────┤     │
 * │  │ encryptedData (12 + fileSize + 16 bytes)               │     │
 * │  │  └─ [12-byte IV][ciphertext][16-byte GCM auth tag]     │     │
 * │  │     AES-256-GCM encrypted file content                 │     │
 * │  └────────────────────────────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * The two components are stored separately so:
 * - encryptedAesKey could theoretically be re-encrypted for a new owner
 * - encryptedData never needs re-processing (AES re-key is cheap)
 *
 * Defensive copies are used in all accessors to prevent external mutation.
 */
public class EncryptedPackage implements Serializable {

    private static final long serialVersionUID = 1L;

    private final byte[] encryptedData;     // IV + AES-GCM ciphertext + tag
    private final byte[] encryptedAesKey;   // RSA-OAEP wrapped AES key
    private final long   encryptTimeMs;     // Measured encryption time (benchmarking)

    /**
     * Creates an EncryptedPackage. Makes defensive copies of all byte arrays.
     */
    public EncryptedPackage(byte[] encryptedData, byte[] encryptedAesKey, long encryptTimeMs) {
        if (encryptedData == null || encryptedAesKey == null) {
            throw new IllegalArgumentException("Encrypted components cannot be null");
        }
        this.encryptedData   = encryptedData.clone();
        this.encryptedAesKey = encryptedAesKey.clone();
        this.encryptTimeMs   = encryptTimeMs;
    }

    /** Returns a defensive copy of the AES-encrypted file bytes. */
    public byte[] getEncryptedData()   { return encryptedData.clone(); }

    /** Returns a defensive copy of the RSA-wrapped AES key bytes. */
    public byte[] getEncryptedAesKey() { return encryptedAesKey.clone(); }

    /** Encryption time in milliseconds (for benchmarking). */
    public long getEncryptTimeMs()     { return encryptTimeMs; }

    /** Total package size (encrypted key + encrypted data). */
    public int getTotalSizeBytes() {
        return encryptedData.length + encryptedAesKey.length;
    }

    @Override
    public String toString() {
        return String.format(
            "EncryptedPackage{encKeySize=%d bytes, dataSize=%d bytes, encTime=%dms}",
            encryptedAesKey.length, encryptedData.length, encryptTimeMs);
    }
}
