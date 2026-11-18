package com.securestorage.storage;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Computes and verifies SHA-256 integrity hashes for file content.
 *
 * Layered integrity model:
 *
 *  Layer 1 — AES-256-GCM authentication tag:
 *    Built into GCM mode. Detects corruption/tampering in the ciphertext.
 *    Throws AEADBadTagException on decrypt if ciphertext is modified.
 *
 *  Layer 2 — SHA-256 hash of plaintext (this class):
 *    Computed BEFORE encryption, stored in FileMetadata.
 *    Verified AFTER decryption against the recovered plaintext.
 *    Detects cases where:
 *    - The encrypted file was replaced with a different user's encrypted file
 *    - Metadata was tampered (pointing to the wrong .enc file)
 *    - Silent data corruption that somehow bypassed the GCM tag
 *
 * This provides defense-in-depth: two independent integrity mechanisms.
 *
 * Uses constant-time comparison to prevent timing side-channel attacks
 * on the hash comparison operation.
 */
public class IntegrityChecker {

    private static final String ALGORITHM = "SHA-256";

    /**
     * Computes a Base64-encoded SHA-256 hash of the given data.
     *
     * @param data Bytes to hash
     * @return     Base64-encoded SHA-256 digest (44 chars)
     */
    public String computeHash(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            byte[] hashBytes     = digest.digest(data);
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed available in all JDK distributions
            throw new RuntimeException("SHA-256 not available on this JVM", e);
        }
    }

    /**
     * Verifies that data matches the expected hash.
     *
     * Uses constant-time comparison to prevent timing attacks.
     *
     * @param data         Bytes to verify
     * @param expectedHash Base64-encoded SHA-256 hash to compare against
     * @return             true if data is intact, false if tampered
     */
    public boolean verify(byte[] data, String expectedHash) {
        String actualHash = computeHash(data);
        return constantTimeEquals(actualHash, expectedHash);
    }

    /**
     * Constant-time string comparison.
     *
     * Standard String.equals() returns as soon as a mismatch is found,
     * which can leak information about where hashes differ (timing oracle).
     * This method always compares all characters.
     */
    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        if (a.length() != b.length()) return false;

        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= (a.charAt(i) ^ b.charAt(i));
        }
        return diff == 0;
    }
}
