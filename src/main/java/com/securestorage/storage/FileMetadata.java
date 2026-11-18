package com.securestorage.storage;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Immutable metadata record for a stored encrypted file.
 *
 * This class does NOT contain file content — only metadata and
 * references needed to locate, verify, and control access to the
 * encrypted file on disk.
 *
 * Fields:
 *  - fileId          Unique ID (UUID) assigned at upload time
 *  - originalName    Filename as submitted by the user
 *  - ownerUsername   The user who uploaded this file (for RBAC checks)
 *  - storagePath     Path to the encrypted .enc file on disk
 *  - integrityHash   SHA-256 hash of the ORIGINAL plaintext (pre-encryption)
 *                    Used to detect tampering after decryption
 *  - originalSizeBytes  Plaintext size in bytes
 *  - uploadedAt      Timestamp
 */
public class FileMetadata implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String        fileId;
    private final String        originalName;
    private final String        ownerUsername;
    private final String        storagePath;
    private final String        integrityHash;      // SHA-256(plaintext), Base64 encoded
    private final long          originalSizeBytes;
    private final LocalDateTime uploadedAt;

    public FileMetadata(String originalName, String ownerUsername,
                        String storagePath, String integrityHash,
                        long originalSizeBytes) {
        this.fileId            = UUID.randomUUID().toString();
        this.originalName      = originalName;
        this.ownerUsername     = ownerUsername;
        this.storagePath       = storagePath;
        this.integrityHash     = integrityHash;
        this.originalSizeBytes = originalSizeBytes;
        this.uploadedAt        = LocalDateTime.now();
    }

    public String        getFileId()             { return fileId; }
    public String        getOriginalName()        { return originalName; }
    public String        getOwnerUsername()       { return ownerUsername; }
    public String        getStoragePath()         { return storagePath; }
    public String        getIntegrityHash()       { return integrityHash; }
    public long          getOriginalSizeBytes()   { return originalSizeBytes; }
    public LocalDateTime getUploadedAt()          { return uploadedAt; }

    @Override
    public String toString() {
        return String.format(
            "FileMetadata{id='%.8s...', name='%s', owner='%s', size=%d B, uploaded=%s}",
            fileId, originalName, ownerUsername, originalSizeBytes, uploadedAt);
    }
}
