package com.securestorage.storage;

import com.securestorage.auth.*;
import com.securestorage.crypto.*;
import com.securestorage.logging.AuditLogger;
import com.securestorage.persistence.MetadataStore;
import com.securestorage.recovery.TransactionLog;
import com.securestorage.utils.InputValidator;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Secure File Storage Engine.
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  User Request                                                   │
 * │   [1] Session validation      AuthManager.getSessionUser        │
 * │   [2] RBAC permission check   AuthManager.requirePermission     │
 * │   [3] Input validation        InputValidator                    │
 * │   [4] Integrity hash          IntegrityChecker.computeHash      │
 * │   [5] Unseal private key      KEK from the session              │
 * │   [6] Hybrid encryption       AES-256-GCM + RSA-2048-OAEP       │
 * │   [7] WAL begin               TransactionLog.logBegin           │
 * │   [8] Persist ciphertext                                        │
 * │   [9] Record + persist metadata                                 │
 * │  [10] WAL commit, audit log                                     │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * ── What changed from v2 ────────────────────────────────────────────
 * 1. The private key is unsealed with the session KEK instead of being read in
 *    plaintext from disk.
 * 2. The metadata index is durable, so uploads survive a restart.
 * 3. Cross-user download now fails with an accurate message. In v2 an ADMIN
 *    passed the permission check and then hit an RSA decryption error, because
 *    it was loading its own key pair to decrypt a file sealed to someone else's
 *    public key. Per-user keys mean an admin can see that a file exists and can
 *    delete it, but cannot read its contents — that is the design working, not
 *    a limitation to paper over.
 */
public class SecureFileStorage {

    private final Path              storageRoot;
    private final HybridEncryption  hybridEncryption;
    private final KeyManager        keyManager;
    private final AuthManager       authManager;
    private final IntegrityChecker  integrityChecker;
    private final AuditLogger       logger;
    private final TransactionLog    transactionLog;
    private final InputValidator    validator;
    private final MetadataStore     metadataStorePersistence;

    /** In-memory file index: fileId → FileMetadata (mirrored to disk). */
    private final Map<String, FileMetadata> metadataStore = new ConcurrentHashMap<>();

    // ═══════════════════════ Construction ════════════════════════

    public SecureFileStorage(String storageDir, AuthManager authManager,
                             AuditLogger logger, TransactionLog txLog) throws Exception {
        this.storageRoot      = Paths.get(storageDir);
        this.hybridEncryption = new HybridEncryption();
        this.keyManager       = new KeyManager(storageDir + "/keys");
        this.authManager      = authManager;
        this.integrityChecker = new IntegrityChecker();
        this.logger           = logger;
        this.transactionLog   = txLog;
        this.validator        = new InputValidator();

        Files.createDirectories(storageRoot.resolve("data"));
        Files.createDirectories(storageRoot.resolve("keys"));

        this.metadataStorePersistence = new MetadataStore(storageDir);
        this.metadataStore.putAll(metadataStorePersistence.load());
        reconcileIndex();
    }

    /**
     * Drops index entries whose ciphertext has gone missing, so the File Manager
     * never offers a download that cannot possibly succeed.
     */
    private void reconcileIndex() {
        List<String> missing = new ArrayList<>();
        metadataStore.forEach((id, meta) -> {
            if (!Files.exists(Paths.get(meta.getStoragePath()))) missing.add(id);
        });
        if (!missing.isEmpty()) {
            missing.forEach(metadataStore::remove);
            persistIndex();
            logger.log("INDEX_RECONCILE", "system",
                "Dropped " + missing.size() + " index entries with no ciphertext on disk");
        }
    }

    // ══════════════════════ Upload File ══════════════════════════

    /**
     * Uploads a file through the full security pipeline.
     * Required permission: UPLOAD_FILE (USER, ADMIN).
     */
    public FileMetadata uploadFile(String sessionToken, String filename,
                                   byte[] fileContent) throws Exception {
        User user = authManager.getSessionUser(sessionToken);
        authManager.requirePermission(user, Permission.UPLOAD_FILE);
        validator.validateFilename(filename);

        String    integrityHash = integrityChecker.computeHash(fileContent);
        SecretKey kek           = requireKek(sessionToken, user);
        KeyPair   keyPair       = keyManager.getOrCreateKeyPair(user.getUserId(), kek);

        EncryptedPackage pkg = hybridEncryption.encrypt(fileContent, keyPair.getPublic());

        String internalId = UUID.randomUUID().toString();
        Path   targetPath = storageRoot.resolve("data").resolve(internalId + ".enc");

        transactionLog.logBegin("UPLOAD", internalId);

        try (ObjectOutputStream oos = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(targetPath.toFile())))) {
            oos.writeObject(pkg);
        } catch (IOException e) {
            transactionLog.logRollback("UPLOAD", internalId);
            throw new IOException("Failed to write encrypted file: " + e.getMessage(), e);
        }

        FileMetadata meta = new FileMetadata(
            filename, user.getUsername(), targetPath.toString(),
            integrityHash, fileContent.length);
        metadataStore.put(meta.getFileId(), meta);
        persistIndex();

        transactionLog.logCommit("UPLOAD", internalId);
        logger.log("UPLOAD", user.getUsername(),
            String.format("'%s' | %d bytes | encTime=%dms | fileId=%s",
                filename, fileContent.length, pkg.getEncryptTimeMs(),
                meta.getFileId().substring(0, 8) + "..."));

        return meta;
    }

    // ══════════════════════ Download File ════════════════════════

    /**
     * Downloads and decrypts a file.
     * Required permission: DOWNLOAD_FILE. Only the owner can decrypt.
     */
    public byte[] downloadFile(String sessionToken, String fileId) throws Exception {
        User user = authManager.getSessionUser(sessionToken);
        authManager.requirePermission(user, Permission.DOWNLOAD_FILE);

        FileMetadata meta = getMetadataOrThrow(fileId);

        if (!meta.getOwnerUsername().equals(user.getUsername())) {
            logger.log("ACCESS_DENIED", user.getUsername(),
                "Cross-user decryption attempt: fileId=" + fileId
                + " (owned by " + meta.getOwnerUsername() + ")");
            throw new SecurityException(
                "This file is encrypted to " + meta.getOwnerUsername() + "'s key pair. "
                + "Even an administrator cannot decrypt it without that user's password — "
                + "per-user keys mean access control is enforced by the cryptography, "
                + "not just by the permission table.");
        }

        EncryptedPackage pkg;
        try (ObjectInputStream ois = new ObjectInputStream(
                new BufferedInputStream(new FileInputStream(meta.getStoragePath())))) {
            // The ciphertext file should contain exactly one EncryptedPackage
            // and its byte arrays — nothing else has any business being here.
            ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
                "maxdepth=8;com.securestorage.crypto.*;[B;java.lang.**;!*"));
            pkg = (EncryptedPackage) ois.readObject();
        }

        SecretKey kek       = requireKek(sessionToken, user);
        KeyPair   keyPair   = keyManager.loadKeyPair(user.getUserId(), kek);
        byte[]    decrypted = hybridEncryption.decrypt(pkg, keyPair.getPrivate());

        if (!integrityChecker.verify(decrypted, meta.getIntegrityHash())) {
            logger.log("INTEGRITY_FAIL", user.getUsername(),
                "Integrity check FAILED for fileId=" + fileId + " — possible tampering");
            throw new SecurityException(
                "File integrity verification failed. File may have been tampered with.");
        }

        logger.log("DOWNLOAD", user.getUsername(),
            String.format("'%s' | %d bytes | fileId=%s",
                meta.getOriginalName(), decrypted.length, fileId.substring(0, 8) + "..."));
        return decrypted;
    }

    // ══════════════════════ Delete File ══════════════════════════

    /** Required permission: DELETE_FILE (ADMIN only). */
    public void deleteFile(String sessionToken, String fileId) throws Exception {
        User user = authManager.getSessionUser(sessionToken);
        authManager.requirePermission(user, Permission.DELETE_FILE);

        FileMetadata meta = getMetadataOrThrow(fileId);
        transactionLog.logBegin("DELETE", fileId);

        Files.deleteIfExists(Paths.get(meta.getStoragePath()));
        metadataStore.remove(fileId);
        persistIndex();

        transactionLog.logCommit("DELETE", fileId);
        logger.log("DELETE", user.getUsername(),
            "Deleted: '" + meta.getOriginalName() + "' (fileId="
            + fileId.substring(0, 8) + "...)");
    }

    // ══════════════════════ List Files ═══════════════════════════

    /** USERs see only their own files. ADMINs see all files (metadata only). */
    public List<FileMetadata> listFiles(String sessionToken) throws Exception {
        User user = authManager.getSessionUser(sessionToken);
        List<FileMetadata> result = new ArrayList<>();
        for (FileMetadata meta : metadataStore.values()) {
            if (user.getRole() == Role.ADMIN
                || meta.getOwnerUsername().equals(user.getUsername())) {
                result.add(meta);
            }
        }
        result.sort(Comparator.comparing(FileMetadata::getUploadedAt).reversed());
        return Collections.unmodifiableList(result);
    }

    // ══════════════════════ Key maintenance ══════════════════════

    /** Re-wraps a user's private key after a password change. */
    public void rewrapUserKey(String userId, SecretKey oldKek, SecretKey newKek) throws Exception {
        if (keyManager.hasKeyPair(userId)) {
            keyManager.rewrap(userId, oldKek, newKek);
            keyManager.evict(userId);
            logger.log("KEY_REWRAP", userId, "Private key re-sealed under the new password");
        }
    }

    /** Clears decrypted private keys from memory. Called on logout. */
    public void clearKeyCache() { keyManager.clearCache(); }

    // ═══════════════════════ Helpers ═════════════════════════════

    private SecretKey requireKek(String sessionToken, User user) {
        SecretKey kek = authManager.getSessionKek(sessionToken);
        if (kek == null) {
            logger.log("ACCESS_DENIED", user.getUsername(),
                "No session key-encryption key — cannot unseal private key");
            throw new SecurityException(
                "Your session has no key-encryption key. Sign out and sign in again.");
        }
        return kek;
    }

    private FileMetadata getMetadataOrThrow(String fileId) {
        FileMetadata meta = metadataStore.get(fileId);
        if (meta == null) {
            throw new IllegalArgumentException("File not found: fileId=" + fileId);
        }
        return meta;
    }

    private void persistIndex() {
        metadataStorePersistence.save(metadataStore);
    }

    public int getFileCount() { return metadataStore.size(); }
}
