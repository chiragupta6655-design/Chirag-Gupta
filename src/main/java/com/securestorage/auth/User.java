package com.securestorage.auth;

import com.securestorage.crypto.KeyDerivation;

import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Represents an authenticated system user.
 *
 * Security features:
 * - Passwords are NEVER stored in plain text (always hashed before construction)
 * - Custom readObject() validates invariants to blunt insecure-deserialization
 *   attacks (CWE-502): without it, a crafted byte stream could deserialize into
 *   a User with role=ADMIN
 * - Fields are final where possible
 *
 * ── New in v3: kekSalt ──────────────────────────────────────────────
 * A second, independent salt used only to derive the Key Encryption Key that
 * seals this user's RSA private key on disk (see {@link KeyDerivation}). It is
 * deliberately NOT the authentication salt: deriving both the stored auth hash
 * and the KEK from one salt with one KDF would mean the stored hash leaks
 * information about the key that protects the private key.
 */
public class User implements Serializable {

    private static final long serialVersionUID = 2L;

    private final String        userId;          // UUID, assigned at creation
    private final String        username;        // Immutable after creation
    private       String        hashedPassword;  // PBKDF2 or BCrypt — never plain text
    private final Role          role;            // Assigned at registration
    private final LocalDateTime createdAt;
    private       boolean       active;          // Can be deactivated by admin
    private       String        kekSalt;         // Base64, for private-key sealing

    /** hashedPassword must already be hashed before calling this. */
    public User(String username, String hashedPassword, Role role) {
        this(username, hashedPassword, role, KeyDerivation.newSaltBase64());
    }

    public User(String username, String hashedPassword, Role role, String kekSalt) {
        this.userId         = UUID.randomUUID().toString();
        this.username       = username;
        this.hashedPassword = hashedPassword;
        this.role           = role;
        this.createdAt      = LocalDateTime.now();
        this.active         = true;
        this.kekSalt        = kekSalt;
    }

    // ─────────────────────────── Getters ───────────────────────────

    public String        getUserId()         { return userId; }
    public String        getUsername()       { return username; }
    public String        getHashedPassword() { return hashedPassword; }
    public Role          getRole()           { return role; }
    public LocalDateTime getCreatedAt()      { return createdAt; }
    public boolean       isActive()          { return active; }
    public String        getKekSalt()        { return kekSalt; }

    public void setActive(boolean active) { this.active = active; }

    /**
     * Replaces the stored hash. Used for transparent rehashing when the system
     * default algorithm changes, and on password change.
     */
    public void setHashedPassword(String hashedPassword) {
        this.hashedPassword = hashedPassword;
    }

    // ────────────────── Secure Deserialization ──────────────────────

    /**
     * Validates all fields after deserialization, so a tampered stream cannot
     * produce a usable privileged object.
     */
    private void readObject(ObjectInputStream in)
            throws java.io.IOException, ClassNotFoundException {
        in.defaultReadObject();

        if (userId == null || userId.isBlank()) {
            throw new InvalidObjectException("userId cannot be null or blank");
        }
        if (username == null || username.isBlank()) {
            throw new InvalidObjectException("username cannot be null or blank");
        }
        if (role == null) {
            throw new InvalidObjectException("role cannot be null");
        }
        if (hashedPassword == null || hashedPassword.length() < 20) {
            throw new InvalidObjectException("hashedPassword appears invalid (too short)");
        }
        // Records written by v2 predate kekSalt; mint one so the account stays
        // usable. Its private key will simply be generated fresh on next upload.
        if (kekSalt == null || kekSalt.isBlank()) {
            kekSalt = KeyDerivation.newSaltBase64();
        }
    }

    @Override
    public String toString() {
        return String.format("User{id='%.8s...', username='%s', role=%s, active=%s, created=%s}",
            userId, username, role, active, createdAt);
    }
}
