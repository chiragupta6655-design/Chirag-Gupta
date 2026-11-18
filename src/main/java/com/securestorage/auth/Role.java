package com.securestorage.auth;

/**
 * Defines the three system roles used in Role-Based Access Control (RBAC).
 *
 * Role hierarchy:
 *   ADMIN   → Full system access (all permissions)
 *   USER    → Upload and download own files only
 *   AUDITOR → View-only access to audit logs
 */
public enum Role {

    /** Full access: read, write, delete files, manage users, view logs. */
    ADMIN,

    /** Standard user: can upload and download their own files only. */
    USER,

    /** Compliance/audit role: read-only access to audit logs, no file access. */
    AUDITOR
}
