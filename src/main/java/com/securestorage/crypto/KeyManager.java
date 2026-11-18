package com.securestorage.crypto;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.security.*;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages RSA-2048 key pairs, with private keys ENCRYPTED AT REST.
 *
 * ── What changed from v2 ────────────────────────────────────────────
 * v2 wrote {userId}.priv as Base64(PKCS#8) in the clear. That made the whole
 * vault readable by anyone who could read the directory.
 *
 * v3 stores:
 *   {userId}.pub   →  Base64(X.509 SubjectPublicKeyInfo)      [public, unprotected]
 *   {userId}.pk8   →  v1:Base64(AES-256-GCM(PKCS#8, KEK))     [encrypted]
 *
 * The KEK comes from {@link KeyDerivation#deriveKek} — derived from the user's
 * password at login and held only in memory. No password, no private key.
 *
 * ── Threat model ────────────────────────────────────────────────────
 * Defends against: offline theft of the storage directory, backup leakage,
 * another local account reading the files.
 * Does NOT defend against: an attacker who already has the user's password, or
 * who can read process memory while a session is open. Those need an HSM or an
 * OS keystore — noted as future work rather than silently pretended.
 */
public class KeyManager {

    private static final String FORMAT_VERSION = "v1";

    private final Path                 keyStoreDir;
    private final RSAEncryption        rsa;
    private final AESEncryption        aes;
    private final Map<String, KeyPair> keyCache = new ConcurrentHashMap<>();

    public KeyManager(String keyStoreDirPath) throws IOException {
        this.keyStoreDir = Paths.get(keyStoreDirPath);
        this.rsa         = new RSAEncryption();
        this.aes         = new AESEncryption();
        Files.createDirectories(keyStoreDir);
        restrictDirectoryPermissions(keyStoreDir);
    }

    // ══════════════════ Key Generation ══════════════════════════

    /**
     * Generates an RSA-2048 key pair and persists it, private key encrypted
     * under the caller's KEK.
     */
    public KeyPair generateAndSaveKeyPair(String userId, SecretKey kek) throws Exception {
        requireKek(kek);
        KeyPair kp = rsa.generateKeyPair();

        Files.writeString(pubPath(userId),
            Base64.getEncoder().encodeToString(rsa.publicKeyToBytes(kp.getPublic())));

        byte[] pkcs8   = rsa.privateKeyToBytes(kp.getPrivate());
        byte[] wrapped = aes.encrypt(pkcs8, kek);
        java.util.Arrays.fill(pkcs8, (byte) 0);      // wipe the plaintext copy

        Files.writeString(privPath(userId),
            FORMAT_VERSION + ":" + Base64.getEncoder().encodeToString(wrapped));

        keyCache.put(userId, kp);
        return kp;
    }

    // ══════════════════ Key Loading ═══════════════════════════════

    /**
     * Loads and decrypts a user's key pair.
     *
     * @throws SecurityException if the KEK is wrong — in practice, the supplied
     *         password does not match the one the key was sealed with. The GCM
     *         auth tag makes this detection exact rather than a guess.
     */
    public KeyPair loadKeyPair(String userId, SecretKey kek) throws Exception {
        requireKek(kek);
        KeyPair cached = keyCache.get(userId);
        if (cached != null) return cached;

        Path pub  = pubPath(userId);
        Path priv = privPath(userId);
        if (!Files.exists(pub) || !Files.exists(priv)) {
            throw new IllegalStateException(
                "No key pair on disk for user " + userId + " — generate one first.");
        }

        PublicKey publicKey = rsa.publicKeyFromBytes(
            Base64.getDecoder().decode(Files.readString(pub).trim()));

        String stored = Files.readString(priv).trim();
        if (!stored.startsWith(FORMAT_VERSION + ":")) {
            throw new IllegalStateException(
                "Private key file for " + userId + " is in an unrecognised format. " +
                "Keys written by v2 were stored unencrypted and cannot be loaded by v3 — " +
                "delete the keys directory to regenerate.");
        }
        byte[] wrapped = Base64.getDecoder().decode(stored.substring(FORMAT_VERSION.length() + 1));

        byte[] pkcs8;
        try {
            pkcs8 = aes.decrypt(wrapped, kek);
        } catch (javax.crypto.AEADBadTagException bad) {
            throw new SecurityException(
                "Could not unlock the private key — the key-encryption key is wrong. " +
                "This normally means the password changed without the key being re-wrapped.");
        }

        PrivateKey privateKey = rsa.privateKeyFromBytes(pkcs8);
        java.util.Arrays.fill(pkcs8, (byte) 0);

        KeyPair kp = new KeyPair(publicKey, privateKey);
        keyCache.put(userId, kp);
        return kp;
    }

    /** Idempotent: returns the existing key pair, or creates one if absent. */
    public KeyPair getOrCreateKeyPair(String userId, SecretKey kek) throws Exception {
        return hasKeyPair(userId) ? loadKeyPair(userId, kek) : generateAndSaveKeyPair(userId, kek);
    }

    public boolean hasKeyPair(String userId) {
        return Files.exists(pubPath(userId)) && Files.exists(privPath(userId));
    }

    /**
     * Re-wraps an existing private key under a new KEK. Must be called whenever
     * the user changes their password, or the key becomes unrecoverable.
     */
    public void rewrap(String userId, SecretKey oldKek, SecretKey newKek) throws Exception {
        KeyPair kp     = loadKeyPair(userId, oldKek);
        byte[] pkcs8   = rsa.privateKeyToBytes(kp.getPrivate());
        byte[] wrapped = aes.encrypt(pkcs8, newKek);
        java.util.Arrays.fill(pkcs8, (byte) 0);
        Files.writeString(privPath(userId),
            FORMAT_VERSION + ":" + Base64.getEncoder().encodeToString(wrapped));
    }

    /** Drops decrypted private keys from memory. Called on logout. */
    public void clearCache() { keyCache.clear(); }

    /** Drops one user's decrypted key from memory. */
    public void evict(String userId) { keyCache.remove(userId); }

    // ══════════════════ Helpers ═══════════════════════════════════

    private Path pubPath(String userId)  { return keyStoreDir.resolve(userId + ".pub"); }
    private Path privPath(String userId) { return keyStoreDir.resolve(userId + ".pk8"); }

    private static void requireKek(SecretKey kek) {
        if (kek == null) {
            throw new SecurityException(
                "No key-encryption key available for this session. Private keys are " +
                "sealed with the owner's password, so this operation can only run as " +
                "the file's owner.");
        }
    }

    private static void restrictDirectoryPermissions(Path dir) {
        try {
            Set<PosixFilePermission> ownerOnly = EnumSet.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE);
            Files.setPosixFilePermissions(dir, ownerOnly);
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows / non-POSIX filesystem — ACLs left at OS defaults.
        }
    }
}
