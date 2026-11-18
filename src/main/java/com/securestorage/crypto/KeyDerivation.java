package com.securestorage.crypto;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Derives a Key Encryption Key (KEK) from a user's password.
 *
 * WHY THIS EXISTS
 * ───────────────
 * In v2 the RSA private keys were written to disk in the clear. Anyone with
 * filesystem access could read every user's private key and therefore decrypt
 * every file in the vault — the encryption was effectively decorative against
 * a local attacker.
 *
 * v3 encrypts each private key with AES-256-GCM under a KEK derived from the
 * owner's password. The KEK is never written to disk; it lives in memory for
 * the duration of a session and is wiped on logout.
 *
 *   password ──PBKDF2-HMAC-SHA256(salt, 210k)──▶ KEK (256-bit)
 *   KEK ──AES-256-GCM──▶ encrypted PKCS#8 private key on disk
 *
 * IMPORTANT: the KEK salt is DIFFERENT from the authentication salt. Reusing
 * one salt for both would mean the stored auth hash and the KEK are derived
 * from the same input with the same parameters, so the stored hash would leak
 * information about the key-encryption key. Two independent salts keep the
 * two derivations cryptographically separate.
 *
 * Iteration count note: 210,000 is the OWASP 2023 floor for PBKDF2-HMAC-SHA256
 * when a second factor is in play; the authentication path uses 310,000. The
 * KEK derivation runs once per login, so this is a deliberate latency choice,
 * not a weakening — both are far above the point where GPU brute force of a
 * strong password is practical.
 */
public final class KeyDerivation {

    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int    ITERATIONS    = 210_000;
    private static final int    KEY_BITS      = 256;
    private static final int    SALT_BYTES    = 16;

    private static final SecureRandom RANDOM = new SecureRandom();

    private KeyDerivation() {}

    /**
     * Generates a fresh random KEK salt, Base64-encoded for storage
     * alongside the user record.
     */
    public static String newSaltBase64() {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Derives the AES-256 Key Encryption Key for a user.
     *
     * @param password   the user's plain-text password (never stored)
     * @param saltBase64 the user's KEK salt, as produced by {@link #newSaltBase64()}
     * @return           a 256-bit AES key used only to wrap/unwrap private keys
     */
    public static SecretKey deriveKek(String password, String saltBase64) {
        if (password == null || saltBase64 == null) {
            throw new IllegalArgumentException("password and salt are required");
        }
        try {
            byte[]     salt    = Base64.getDecoder().decode(saltBase64);
            PBEKeySpec spec    = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_BITS);
            SecretKeyFactory f = SecretKeyFactory.getInstance(KDF_ALGORITHM);
            byte[]     keyBytes = f.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            throw new IllegalStateException("KEK derivation failed", e);
        }
    }

    /** Human-readable description of the KDF parameters, for the UI and audit trail. */
    public static String describe() {
        return KDF_ALGORITHM + " / " + String.format("%,d", ITERATIONS) + " iterations / "
             + KEY_BITS + "-bit KEK";
    }
}
