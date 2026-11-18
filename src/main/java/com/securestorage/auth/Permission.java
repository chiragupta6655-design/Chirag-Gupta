package com.securestorage.auth;

/**
 * Granular permissions that can be assigned to roles.
 *
 * RBAC mapping (defined in AuthManager):
 *
 *  ADMIN   → ALL permissions
 *  USER    → UPLOAD_FILE, DOWNLOAD_FILE
 *  AUDITOR → VIEW_LOGS
 *
 * This separation follows the Principle of Least Privilege:
 * each role receives only the permissions it needs to operate.
 */
public enum Permission {

    /** Upload new files to secure storage. */
    UPLOAD_FILE,

    /** Download and decrypt files from secure storage. */
    DOWNLOAD_FILE,

    /** Delete files (admin-only to prevent accidental loss). */
    DELETE_FILE,

    /** View all files across all users (admin-only). */
    VIEW_ALL_FILES,

    /** Create/deactivate user accounts. */
    MANAGE_USERS,

    /** Read the audit log trail. */
    VIEW_LOGS,

    /** Trigger checkpoint saves and recoveries. */
    CREATE_CHECKPOINT
}
