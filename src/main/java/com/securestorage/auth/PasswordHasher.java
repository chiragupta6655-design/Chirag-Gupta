package com.securestorage.auth;

import org.mindrot.jbcrypt.BCrypt;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Password hashing with two interchangeable algorithms.
 *
 * ── What changed from v2 ────────────────────────────────────────────
 * v2 implemented BCrypt but never used it: AuthManager called hashPBKDF2()
 * exclusively, so BCrypt existed only inside the benchmark. Describing it as
 * an authentication mechanism in a paper would have been inaccurate.
 *
 * v3 makes the choice real. {@link #hash} takes an algorithm, the system-wide
 * default is configurable, and {@link #verify} identifies the algorithm from
 * the stored string itself — so a vault can hold PBKDF2 and BCrypt records side
 * by side and both log in correctly. That also makes algorithm migration
 * possible: change the default, and each user's hash upgrades on next login.
 *
 * ┌──────────────────┬───────────────────────────────────────────────────┐
 * │ PBKDF2-SHA256    │ NIST SP 800-132, 310,000 iterations, JDK built-in │
 * │ BCrypt           │ Blowfish-based, adaptive cost 12, widely audited  │
 * └──────────────────┴───────────────────────────────────────────────────┘
 *
 * Both salt randomly and compare in constant time. The point of both is
 * deliberate slowness: a fast hash is the vulnerability, not the feature.
 *
 * Stored formats:
 *   PBKDF2 →  pbkdf2-sha256$310000$&lt;b64 salt&gt;$&lt;b64 hash&gt;
 *   BCrypt →  $2a$12$&lt;22-char salt&gt;&lt;31-char hash&gt;   (BCrypt's own format)
 */
public class PasswordHasher {

    /** Supported password hashing algorithms. */
    public enum Algorithm {
        PBKDF2("PBKDF2-SHA256 (310,000 iterations)"),
        BCRYPT("BCrypt (cost 12)");

        public final String description;
        Algorithm(String d) { this.description = d; }
    }

    // ─────────────────── Parameters ──────────────────────────────
    private static final int PBKDF2_ITERATIONS = 310_000;   // OWASP 2023 floor
    private static final int PBKDF2_KEY_LENGTH = 256;       // bits
    private static final int SALT_BYTES        = 16;        // 128-bit salt
    private static final int BCRYPT_COST       = 12;        // 2^12 rounds

    private static final String PBKDF2_PREFIX = "pbkdf2-sha256";

    private final SecureRandom secureRandom = new SecureRandom();

    /** System-wide default. Changing this changes what new/rehashed passwords use. */
    private Algorithm defaultAlgorithm = Algorithm.PBKDF2;

    public Algorithm getDefaultAlgorithm()             { return defaultAlgorithm; }
    public void setDefaultAlgorithm(Algorithm alg)     { this.defaultAlgorithm = alg; }

    // ═══════════════════ Unified API ═════════════════════════════

    /** Hashes with the configured default algorithm. */
    public String hash(String plainPassword) {
        return hash(plainPassword, defaultAlgorithm);
    }

    /** Hashes with a specific algorithm. */
    public String hash(String plainPassword, Algorithm algorithm) {
        return switch (algorithm) {
            case PBKDF2 -> hashPBKDF2(plainPassword);
            case BCRYPT -> hashBCrypt(plainPassword);
        };
    }

    /**
     * Verifies a password against any stored hash, identifying the algorithm
     * from the stored string. Returns false rather than throwing on a malformed
     * record — an unparseable hash is a failed login, not a crash.
     */
    public boolean verify(String plainPassword, String storedHash) {
        if (plainPassword == null || storedHash == null || storedHash.isBlank()) return false;
        try {
            Algorithm alg = identify(storedHash);
            if (alg == null) return false;
            return switch (alg) {
                case PBKDF2 -> verifyPBKDF2(plainPassword, storedHash);
                case BCRYPT -> verifyBCrypt(plainPassword, storedHash);
            };
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Identifies which algorithm produced a stored hash, or null if unrecognised. */
    public Algorithm identify(String storedHash) {
        if (storedHash == null) return null;
        if (storedHash.startsWith("$2a$") || storedHash.startsWith("$2b$")
                || storedHash.startsWith("$2y$")) {
            return Algorithm.BCRYPT;
        }
        if (storedHash.startsWith(PBKDF2_PREFIX + "$")) return Algorithm.PBKDF2;
        // v2 legacy format: Base64(salt) ":" Base64(hash)
        if (storedHash.chars().filter(c -> c == ':').count() == 1) return Algorithm.PBKDF2;
        return null;
    }

    /**
     * True when a stored hash was produced by something other than the current
     * default — the caller can then transparently re-hash on successful login.
     */
    public boolean needsRehash(String storedHash) {
        Algorithm alg = identify(storedHash);
        return alg == null || alg != defaultAlgorithm
            || (alg == Algorithm.PBKDF2 && !storedHash.startsWith(PBKDF2_PREFIX + "$"));
    }

    // ═══════════════════════════ PBKDF2 ══════════════════════════

    /** Hashes using PBKDF2WithHmacSHA256, in the self-describing v3 format. */
    public String hashPBKDF2(String plainPassword) {
        byte[] salt = generateSalt();
        byte[] hash = derivePBKDF2Key(plainPassword.toCharArray(), salt, PBKDF2_ITERATIONS);
        return PBKDF2_PREFIX + "$" + PBKDF2_ITERATIONS + "$"
             + Base64.getEncoder().encodeToString(salt) + "$"
             + Base64.getEncoder().encodeToString(hash);
    }

    /** Verifies against either the v3 format or the v2 {@code salt:hash} format. */
    public boolean verifyPBKDF2(String plainPassword, String storedHash) {
        byte[] salt, expected;
        int iterations;

        if (storedHash.startsWith(PBKDF2_PREFIX + "$")) {
            String[] parts = storedHash.split("\\$");
            if (parts.length != 4) return false;
            iterations = Integer.parseInt(parts[1]);
            salt       = Base64.getDecoder().decode(parts[2]);
            expected   = Base64.getDecoder().decode(parts[3]);
        } else {
            String[] parts = storedHash.split(":");
            if (parts.length != 2) return false;
            iterations = PBKDF2_ITERATIONS;
            salt       = Base64.getDecoder().decode(parts[0]);
            expected   = Base64.getDecoder().decode(parts[1]);
        }

        byte[] actual = derivePBKDF2Key(plainPassword.toCharArray(), salt, iterations);
        return constantTimeEquals(expected, actual);
    }

    private byte[] derivePBKDF2Key(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = null;
        try {
            spec = new PBEKeySpec(password, salt, iterations, PBKDF2_KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("PBKDF2 key derivation failed", e);
        } finally {
            if (spec != null) spec.clearPassword();
        }
    }

    // ═══════════════════════════ BCrypt ══════════════════════════

    public String hashBCrypt(String plainPassword) {
        return BCrypt.hashpw(plainPassword, BCrypt.gensalt(BCRYPT_COST));
    }

    /** BCrypt.checkpw compares in constant time internally. */
    public boolean verifyBCrypt(String plainPassword, String storedHash) {
        try {
            return BCrypt.checkpw(plainPassword, storedHash);
        } catch (IllegalArgumentException e) {
            return false;   // malformed salt in the stored record
        }
    }

    // ═══════════════════════ Utility Helpers ═════════════════════

    private byte[] generateSalt() {
        byte[] salt = new byte[SALT_BYTES];
        secureRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Constant-time byte comparison. A naive equals() returns early on the first
     * mismatch, leaking how many bytes matched; this always does the full pass.
     */
    private boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= (a[i] ^ b[i]);
        return diff == 0;
    }

    /** Parameter summary for the UI and for reporting in the paper. */
    public static String describe(Algorithm alg) {
        return switch (alg) {
            case PBKDF2 -> "PBKDF2-HMAC-SHA256, " + String.format("%,d", PBKDF2_ITERATIONS)
                         + " iterations, " + PBKDF2_KEY_LENGTH + "-bit output, "
                         + (SALT_BYTES * 8) + "-bit salt";
            case BCRYPT -> "BCrypt (Blowfish), cost factor " + BCRYPT_COST
                         + " = 2^" + BCRYPT_COST + " rounds, 128-bit salt";
        };
    }
}
