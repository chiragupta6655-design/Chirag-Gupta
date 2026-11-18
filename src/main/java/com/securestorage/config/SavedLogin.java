package com.securestorage.config;

import com.securestorage.crypto.AESEncryption;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Properties;
import java.util.Set;

/**
 * Remembers the login so you are not retyping credentials on every launch.
 *
 * ── Two levels, and an honest description of each ───────────────────
 *
 * 1. Remember username (default on). Zero risk — a username is not a secret.
 *
 * 2. Remember password (opt-in, off by default). The password is encrypted with
 *    AES-256-GCM under a random 256-bit device key held in a separate file.
 *
 * Be clear-eyed about what level 2 actually buys: the device key sits on the
 * same disk as the encrypted password, so anyone who can read your user account
 * can read both and recover the password. It stops a password appearing in
 * plain text in a config file, a screen share, or a backup someone skims. It
 * does NOT stop an attacker who already has access to your account.
 *
 * Real protection would mean the OS credential store — DPAPI on Windows,
 * Keychain on macOS, libsecret on Linux — which is platform-specific native
 * work and is left as future work rather than misrepresented here. The UI says
 * the same thing next to the checkbox, so the choice is informed.
 *
 * Never stored: session tokens, key-encryption keys, or any private key.
 */
public class SavedLogin {

    private static final String FILE_NAME   = "session.properties";
    private static final String KEY_FILE    = ".device.key";

    private static final String K_USERNAME  = "remember.username";
    private static final String K_PASSWORD  = "remember.password.enc";
    private static final String K_ENABLED   = "remember.enabled";
    private static final String K_SAVE_PASS = "remember.password.enabled";
    private static final String K_LAST_SEEN = "last.login";

    private final Path baseDir;
    private final Path file;
    private final Path keyFile;
    private final Properties props = new Properties();
    private final AESEncryption aes = new AESEncryption();

    public SavedLogin(String baseDir) {
        this.baseDir = Paths.get(baseDir);
        this.file    = this.baseDir.resolve(FILE_NAME);
        this.keyFile = this.baseDir.resolve(KEY_FILE);
        load();
    }

    // ── Public API ───────────────────────────────────────────────────

    public boolean isEnabled()          { return Boolean.parseBoolean(props.getProperty(K_ENABLED, "false")); }
    public boolean isPasswordSaved()    { return Boolean.parseBoolean(props.getProperty(K_SAVE_PASS, "false")); }
    public String  getUsername()        { return props.getProperty(K_USERNAME, ""); }
    public String  getLastLogin()       { return props.getProperty(K_LAST_SEEN, ""); }

    /** Returns the remembered password, or empty string if none is stored or it cannot be read. */
    public String getPassword() {
        String blob = props.getProperty(K_PASSWORD, "");
        if (blob.isBlank()) return "";
        try {
            SecretKey deviceKey = loadOrCreateDeviceKey();
            byte[] plain = aes.decrypt(Base64.getDecoder().decode(blob), deviceKey);
            return new String(plain, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Device key rotated, file corrupted, or copied from another machine.
            props.remove(K_PASSWORD);
            save();
            return "";
        }
    }

    /**
     * Saves the login preference.
     *
     * @param username     the username to remember
     * @param password     the password, or null when only the username is remembered
     * @param savePassword whether the password should be stored at all
     */
    public void remember(String username, String password, boolean savePassword) {
        props.setProperty(K_ENABLED, "true");
        props.setProperty(K_USERNAME, username == null ? "" : username);
        props.setProperty(K_LAST_SEEN, java.time.LocalDateTime.now().toString());

        if (savePassword && password != null && !password.isEmpty()) {
            try {
                SecretKey deviceKey = loadOrCreateDeviceKey();
                byte[] enc = aes.encrypt(
                    password.getBytes(java.nio.charset.StandardCharsets.UTF_8), deviceKey);
                props.setProperty(K_PASSWORD, Base64.getEncoder().encodeToString(enc));
                props.setProperty(K_SAVE_PASS, "true");
            } catch (Exception e) {
                props.remove(K_PASSWORD);
                props.setProperty(K_SAVE_PASS, "false");
            }
        } else {
            props.remove(K_PASSWORD);
            props.setProperty(K_SAVE_PASS, "false");
        }
        save();
    }

    /** Forgets everything, including the stored password. */
    public void forget() {
        props.clear();
        props.setProperty(K_ENABLED, "false");
        save();
        try { Files.deleteIfExists(keyFile); } catch (IOException ignored) { }
    }

    // ── Storage ──────────────────────────────────────────────────────

    private void load() {
        if (!Files.exists(file)) return;
        try (var in = Files.newInputStream(file)) {
            props.load(in);
        } catch (IOException e) {
            System.err.println("[SavedLogin] Could not read " + file + ": " + e.getMessage());
        }
    }

    private void save() {
        try {
            Files.createDirectories(baseDir);
            try (var out = Files.newOutputStream(file)) {
                props.store(out, "SecureVault saved login — passwords here are encrypted "
                    + "under a local device key, which is NOT protection against someone "
                    + "who already has access to this user account.");
            }
            restrictToOwner(file);
        } catch (IOException e) {
            System.err.println("[SavedLogin] Could not write " + file + ": " + e.getMessage());
        }
    }

    private SecretKey loadOrCreateDeviceKey() throws IOException {
        if (Files.exists(keyFile)) {
            byte[] raw = Base64.getDecoder().decode(Files.readString(keyFile).trim());
            if (raw.length == 32) return new SecretKeySpec(raw, "AES");
        }
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        Files.createDirectories(baseDir);
        Files.writeString(keyFile, Base64.getEncoder().encodeToString(raw));
        restrictToOwner(keyFile);
        return new SecretKeySpec(raw, "AES");
    }

    private static void restrictToOwner(Path p) {
        try {
            Set<PosixFilePermission> ownerOnly =
                EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(p, ownerOnly);
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows / non-POSIX — left at OS defaults.
        }
    }
}
