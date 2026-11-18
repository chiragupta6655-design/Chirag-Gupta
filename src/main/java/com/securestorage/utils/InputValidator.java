package com.securestorage.utils;

import java.io.File;
import java.io.IOException;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Input validation and sanitization to defend against common injection attacks.
 *
 * Defenses implemented:
 *
 * ┌────────────────────────────────────────────────────────────────────┐
 * │ Attack              │ Defense                                      │
 * ├────────────────────────────────────────────────────────────────────┤
 * │ Path Traversal      │ Canonical path validation against base dir   │
 * │  ../../etc/passwd   │ Rejects if resolved path escapes storage dir │
 * ├────────────────────────────────────────────────────────────────────┤
 * │ Malicious Upload    │ Extension whitelist (only safe types allowed)│
 * │  shell.php, .exe   │ Blocks dangerous executable extensions       │
 * ├────────────────────────────────────────────────────────────────────┤
 * │ SQL Injection       │ Pattern detection for SQL keywords           │
 * │  ' OR 1=1 --       │ (even in file-based systems for filename use)│
 * ├────────────────────────────────────────────────────────────────────┤
 * │ Command Injection   │ Pattern detection for shell metacharacters   │
 * │  file.csv; rm -rf  │ Blocks ;, |, &, `, $(), etc.                 │
 * └────────────────────────────────────────────────────────────────────┘
 *
 * All validation failures throw descriptive exceptions — they are caught
 * in the attack simulator to demonstrate the defense working.
 */
public class InputValidator {

    // ─────────────────── Filename Rules ──────────────────────────

    /** Allowed file extensions whitelist (principle of least privilege). */
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of(
        ".txt", ".pdf", ".png", ".jpg", ".jpeg",
        ".csv", ".json", ".xml", ".log", ".md"
    );

    /** Characters forbidden in filenames. */
    private static final Pattern DANGEROUS_FILENAME_CHARS =
        Pattern.compile("[/\\\\:*?\"<>|\\x00-\\x1F]");

    /** Path traversal sequence patterns. */
    private static final Pattern PATH_TRAVERSAL =
        Pattern.compile("\\.\\.|%2e%2e|%252e|\\.\\.%2f|%2e%2e/|%2e%2e%5c",
                        Pattern.CASE_INSENSITIVE);

    private static final int MAX_FILENAME_LENGTH = 255;

    // ─────────────────── Injection Patterns ──────────────────────

    /** SQL injection keyword detection (for filenames, metadata, usernames). */
    private static final Pattern SQL_INJECTION =
        Pattern.compile(
            "(?i)\\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|" +
            "UNION|TRUNCATE|SCRIPT|DECLARE)\\b|'\\s*(OR|AND)|--\\s*$|;\\s*--",
            Pattern.MULTILINE);

    /** Command injection: shell metacharacters and dangerous commands. */
    private static final Pattern CMD_INJECTION =
        Pattern.compile("[;&|`$(){}\\[\\]]|\\bsudo\\b|\\brm\\s+-rf\\b|\\bchmod\\b|" +
                        "\\bwget\\b|\\bcurl\\b|\\beval\\b",
                        Pattern.CASE_INSENSITIVE);

    // ══════════════════════ Filename Validation ═══════════════════

    /**
     * Validates a filename for safe storage.
     *
     * Checks:
     *  1. Not null/blank
     *  2. Length ≤ 255 characters
     *  3. No forbidden characters (/, \, :, *, ?, ", <, >, |, control chars)
     *  4. No path traversal sequences (.. patterns)
     *  5. Extension in whitelist
     *
     * @param filename The filename to validate
     * @throws IllegalArgumentException on any violation
     */
    public void validateFilename(String filename) {
        if (filename == null || filename.isBlank()) {
            throw new IllegalArgumentException("Filename cannot be null or blank");
        }
        if (filename.length() > MAX_FILENAME_LENGTH) {
            throw new IllegalArgumentException(
                "Filename too long: " + filename.length() + " chars (max " + MAX_FILENAME_LENGTH + ")");
        }
        if (DANGEROUS_FILENAME_CHARS.matcher(filename).find()) {
            throw new IllegalArgumentException(
                "Filename contains illegal characters: '" + filename + "'");
        }
        if (PATH_TRAVERSAL.matcher(filename).find()) {
            throw new IllegalArgumentException(
                "Path traversal pattern detected in filename: '" + filename + "'");
        }

        // Extension whitelist check
        String lower = filename.toLowerCase();
        boolean extensionAllowed = ALLOWED_EXTENSIONS.stream().anyMatch(lower::endsWith);
        if (!extensionAllowed) {
            throw new IllegalArgumentException(
                "File extension not permitted. Allowed: " + ALLOWED_EXTENSIONS +
                ". Got: '" + filename + "'");
        }
    }

    // ══════════════════════ Path Traversal ═══════════════════════

    /**
     * Validates that a user-supplied path component stays within a base directory.
     *
     * Attack: Attacker submits "../../etc/passwd" hoping to read system files.
     * Defense: Canonicalize both paths and verify containment.
     *
     * Why canonicalize?
     *   new File("/storage/data/../../../etc/passwd").getCanonicalPath()
     *   → "/etc/passwd" (OS resolves the traversal)
     *   Comparing raw strings would miss this.
     *
     * @param baseDir   Trusted base directory (e.g., "/storage/data")
     * @param userInput User-supplied filename/path component
     * @throws SecurityException if resolved path escapes the base directory
     * @throws IOException       on filesystem access error
     */
    public void validatePath(String baseDir, String userInput) throws IOException {
        File base   = new File(baseDir).getCanonicalFile();
        File target = new File(baseDir, userInput).getCanonicalFile();

        String basePath   = base.getPath() + File.separator;
        String targetPath = target.getPath();

        // Allow exact match (baseDir itself) or files within it
        boolean safe = targetPath.startsWith(basePath) ||
                       targetPath.equals(base.getPath());

        if (!safe) {
            throw new SecurityException(
                "Path traversal detected! Input '" + userInput +
                "' resolves to '" + targetPath + "' which is outside '" + base.getPath() + "'");
        }
    }

    // ══════════════════════ Injection Detection ═══════════════════

    /**
     * Returns true if the input contains SQL injection patterns.
     * Even in file-based systems, filenames may end up in queries or logs.
     *
     * @param input String to check
     * @return      true if SQL injection pattern detected
     */
    public boolean detectsSqlInjection(String input) {
        if (input == null) return false;
        return SQL_INJECTION.matcher(input).find();
    }

    /**
     * Returns true if the input contains command injection patterns.
     *
     * @param input String to check
     * @return      true if command injection pattern detected
     */
    public boolean detectsCommandInjection(String input) {
        if (input == null) return false;
        return CMD_INJECTION.matcher(input).find();
    }

    /**
     * Sanitizes a string by removing known dangerous characters.
     * Used as a secondary defense; always prefer rejecting over sanitizing.
     *
     * @param input Raw user input
     * @return      Sanitized string with dangerous chars removed
     */
    public String sanitize(String input) {
        if (input == null) return "";
        return input.replaceAll("[<>\"'&;`|\\\\]", "").trim();
    }
}
