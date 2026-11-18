package com.securestorage.auth;

import com.securestorage.crypto.KeyDerivation;
import com.securestorage.logging.AuditLogger;
import com.securestorage.persistence.UserStore;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Central authentication and authorization manager.
 *
 * Responsibilities:
 *  - User registration with password strength validation
 *  - Session-based authentication (UUID tokens)
 *  - Per-session Key Encryption Keys, so private keys stay sealed at rest
 *  - Static RBAC permission mapping (Role → Set&lt;Permission&gt;)
 *  - Durable user storage
 *  - Audit logging for all auth events
 *
 * ── What changed from v2 ────────────────────────────────────────────
 * 1. Users persist. v2 rebuilt an empty map on every start and re-seeded admin,
 *    so registered accounts silently disappeared.
 * 2. Login derives a KEK from the password and holds it for the session. That
 *    KEK is the only thing that can unlock the user's RSA private key, which is
 *    now encrypted on disk.
 * 3. Password hashing is selectable and self-describing, and a hash produced by
 *    a non-default algorithm is transparently upgraded on the next successful
 *    login.
 *
 * Thread-safety: ConcurrentHashMap throughout.
 *
 * Security model (Principle of Least Privilege):
 *   ADMIN   → ALL permissions
 *   USER    → UPLOAD_FILE, DOWNLOAD_FILE only
 *   AUDITOR → VIEW_LOGS only
 */
public class AuthManager {

    public static final String DEFAULT_ADMIN_USERNAME = "admin";
    public static final String DEFAULT_ADMIN_PASSWORD = "Admin@Secure123!";

    // ── Storage ──────────────────────────────────────────────────
    private final Map<String, User>      users          = new ConcurrentHashMap<>();
    private final Map<String, String>    activeSessions = new ConcurrentHashMap<>(); // token → username
    private final Map<String, SecretKey> sessionKeks    = new ConcurrentHashMap<>(); // token → KEK

    private final PasswordHasher passwordHasher;
    private final AuditLogger    logger;
    private final UserStore      userStore;   // null ⇒ in-memory only (tests, benchmarks)

    // ── Static RBAC Permission Table ─────────────────────────────
    private static final Map<Role, Set<Permission>> ROLE_PERMISSIONS;

    static {
        ROLE_PERMISSIONS = new EnumMap<>(Role.class);
        ROLE_PERMISSIONS.put(Role.ADMIN, EnumSet.allOf(Permission.class));
        ROLE_PERMISSIONS.put(Role.USER, EnumSet.of(
            Permission.UPLOAD_FILE,
            Permission.DOWNLOAD_FILE,
            Permission.CREATE_CHECKPOINT));
        ROLE_PERMISSIONS.put(Role.AUDITOR, EnumSet.of(
            Permission.VIEW_LOGS));
    }

    // ── Constructors ──────────────────────────────────────────────

    /** In-memory only. Used by benchmarks and tests. */
    public AuthManager(AuditLogger logger) {
        this(logger, null);
    }

    /**
     * @param logger    audit logger
     * @param userStore durable store, or null for in-memory operation
     */
    public AuthManager(AuditLogger logger, UserStore userStore) {
        this.passwordHasher = new PasswordHasher();
        this.logger         = logger;
        this.userStore      = userStore;

        if (userStore != null) {
            users.putAll(userStore.load());
        }
        if (!users.containsKey(DEFAULT_ADMIN_USERNAME)) {
            registerUser(DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD, Role.ADMIN);
        }
    }

    // ══════════════════════ Registration ═════════════════════════

    /**
     * Registers a new user with a hashed password and a fresh KEK salt.
     *
     * @throws IllegalArgumentException if username taken or password weak
     */
    public User registerUser(String username, String password, Role role) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username cannot be empty");
        }
        String name = username.trim();
        if (users.containsKey(name)) {
            throw new IllegalArgumentException("Username already exists: " + name);
        }
        validatePasswordStrength(password);

        User user = new User(name, passwordHasher.hash(password), role);
        users.put(name, user);
        persist();

        logger.log("REGISTER", "system",
            String.format("New user registered: '%s' [%s] hash=%s",
                name, role, passwordHasher.getDefaultAlgorithm()));
        return user;
    }

    // ══════════════════════ Authentication ═══════════════════════

    /**
     * Authenticates a user and opens a session.
     *
     * Security notes:
     * - Constant-time password comparison, inside PasswordHasher
     * - Generic error message, to avoid username enumeration
     * - All failures logged for intrusion detection
     * - Derives the session KEK; without it the user's private key stays sealed
     *
     * @return session token (UUID string)
     * @throws SecurityException on invalid credentials
     */
    public String login(String username, String password) {
        String name = username == null ? "" : username.trim();
        User user = users.get(name);

        if (user == null || !user.isActive()) {
            logger.log("LOGIN_FAIL", "unknown",
                "Login attempt for unknown/inactive user: " + name);
            throw new SecurityException("Invalid credentials");
        }

        if (!passwordHasher.verify(password, user.getHashedPassword())) {
            logger.log("LOGIN_FAIL", name, "Incorrect password attempt");
            throw new SecurityException("Invalid credentials");
        }

        // Transparent upgrade: re-hash under the current default algorithm.
        if (passwordHasher.needsRehash(user.getHashedPassword())) {
            user.setHashedPassword(passwordHasher.hash(password));
            persist();
            logger.log("REHASH", name,
                "Password hash upgraded to " + passwordHasher.getDefaultAlgorithm());
        }

        String token = UUID.randomUUID().toString();
        activeSessions.put(token, name);
        sessionKeks.put(token, KeyDerivation.deriveKek(password, user.getKekSalt()));

        logger.log("LOGIN", name, "Session created: " + token.substring(0, 8) + "...");
        return token;
    }

    /** Terminates a session and wipes its KEK from memory. */
    public void logout(String token) {
        String username = activeSessions.remove(token);
        sessionKeks.remove(token);
        if (username != null) {
            logger.log("LOGOUT", username, "Session terminated");
        }
    }

    // ══════════════════════ Authorization ════════════════════════

    public User getSessionUser(String token) {
        String username = activeSessions.get(token);
        if (username == null) {
            throw new SecurityException("Invalid or expired session token");
        }
        User user = users.get(username);
        if (user == null || !user.isActive()) {
            activeSessions.remove(token);
            sessionKeks.remove(token);
            throw new SecurityException("User account is inactive");
        }
        return user;
    }

    /**
     * Returns the Key Encryption Key for this session, or null if the session is
     * unknown. Callers that need to touch a private key must treat null as a
     * hard stop, not a warning.
     */
    public SecretKey getSessionKek(String token) {
        return sessionKeks.get(token);
    }

    public boolean hasPermission(User user, Permission permission) {
        return ROLE_PERMISSIONS
            .getOrDefault(user.getRole(), EnumSet.noneOf(Permission.class))
            .contains(permission);
    }

    /** Primary RBAC enforcement point. Storage operations call this first. */
    public void requirePermission(User user, Permission permission) {
        if (!hasPermission(user, permission)) {
            logger.log("ACCESS_DENIED", user.getUsername(),
                String.format("Role [%s] lacks permission: %s", user.getRole(), permission));
            throw new SecurityException(
                String.format("Access denied: role [%s] cannot perform [%s]",
                    user.getRole(), permission));
        }
        logger.log("ACCESS_GRANTED", user.getUsername(), "Permission granted: " + permission);
    }

    /** The full permission set for a role — used to build the navigation menu. */
    public static Set<Permission> permissionsFor(Role role) {
        return Collections.unmodifiableSet(
            ROLE_PERMISSIONS.getOrDefault(role, EnumSet.noneOf(Permission.class)));
    }

    // ══════════════════════ Admin Operations ═════════════════════

    public void deactivateUser(String username) {
        User user = users.get(username);
        if (user == null) throw new IllegalArgumentException("User not found: " + username);
        if (DEFAULT_ADMIN_USERNAME.equals(username)) {
            throw new IllegalArgumentException("The default admin account cannot be deactivated");
        }
        user.setActive(false);
        activeSessions.entrySet().removeIf(e -> {
            boolean match = e.getValue().equals(username);
            if (match) sessionKeks.remove(e.getKey());
            return match;
        });
        persist();
        logger.log("DEACTIVATE", "admin", "Deactivated user: " + username);
    }

    public void reactivateUser(String username) {
        User user = users.get(username);
        if (user == null) throw new IllegalArgumentException("User not found: " + username);
        user.setActive(true);
        persist();
        logger.log("REACTIVATE", "admin", "Reactivated user: " + username);
    }

    /**
     * Changes a password and returns the old and new KEKs, so the caller can
     * re-wrap the user's private key.
     *
     * Skipping the re-wrap step makes every file that user owns permanently
     * undecryptable, which is why the KEKs are handed back rather than the
     * change being fire-and-forget.
     */
    public SecretKey[] changePassword(String username, String oldPassword, String newPassword) {
        User user = users.get(username);
        if (user == null) throw new IllegalArgumentException("User not found: " + username);
        if (!passwordHasher.verify(oldPassword, user.getHashedPassword())) {
            logger.log("PASSWORD_CHANGE_FAIL", username, "Old password incorrect");
            throw new SecurityException("Current password is incorrect");
        }
        validatePasswordStrength(newPassword);

        SecretKey oldKek = KeyDerivation.deriveKek(oldPassword, user.getKekSalt());
        SecretKey newKek = KeyDerivation.deriveKek(newPassword, user.getKekSalt());

        user.setHashedPassword(passwordHasher.hash(newPassword));
        persist();
        logger.log("PASSWORD_CHANGE", username, "Password updated; private key re-wrap required");
        return new SecretKey[]{oldKek, newKek};
    }

    // ═══════════════════════ Helpers ═════════════════════════════

    /** Min 8 chars, uppercase, digit, special character. */
    private void validatePasswordStrength(String password) {
        if (password == null || password.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }
        if (!password.matches(".*[A-Z].*")) {
            throw new IllegalArgumentException("Password must contain at least one uppercase letter");
        }
        if (!password.matches(".*[0-9].*")) {
            throw new IllegalArgumentException("Password must contain at least one digit");
        }
        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\",./<>?].*")) {
            throw new IllegalArgumentException(
                "Password must contain at least one special character (!@#$% etc.)");
        }
    }

    private void persist() {
        if (userStore != null) userStore.save(users);
    }

    // ════════════════════════ Accessors ══════════════════════════

    public PasswordHasher getPasswordHasher()  { return passwordHasher; }
    public Collection<User> getAllUsers()      { return Collections.unmodifiableCollection(users.values()); }
    public int getActiveSessionCount()         { return activeSessions.size(); }
    public boolean isPersistent()              { return userStore != null; }
}
