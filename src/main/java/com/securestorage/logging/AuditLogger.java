package com.securestorage.logging;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe, dual-output audit logger.
 *
 * Writes structured log entries to:
 *   1. In-memory list  → for real-time queries (Auditor role access)
 *   2. Persistent file → for compliance and forensic trail (logs/audit.log)
 *
 * Log format: [TIMESTAMP] [ACTION          ] [USER        ] message
 *
 * Actions logged throughout the system:
 *   REGISTER, LOGIN, LOGIN_FAIL, LOGOUT
 *   UPLOAD, DOWNLOAD, DELETE
 *   ACCESS_GRANTED, ACCESS_DENIED
 *   INTEGRITY_FAIL, CHECKPOINT, RECOVERY
 *
 * Thread-safety:
 *   - CopyOnWriteArrayList for in-memory log (safe for concurrent reads)
 *   - PrintWriter with autoFlush
 *   - synchronized log() method
 */
public class AuditLogger {

    private static final DateTimeFormatter TIMESTAMP_FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final Path                logFilePath;
    private final List<LogEntry>      inMemoryLog = new CopyOnWriteArrayList<>();
    private final PrintWriter         writer;

    /**
     * @param logDir Directory where audit.log will be written
     * @throws IOException if log file cannot be created
     */
    public AuditLogger(String logDir) throws IOException {
        Files.createDirectories(Paths.get(logDir));
        this.logFilePath = Paths.get(logDir, "audit.log");
        // append=true preserves log across restarts; autoFlush=true for crash safety
        this.writer = new PrintWriter(
            new FileWriter(logFilePath.toFile(), true), true);
    }

    // ══════════════════════ Logging API ══════════════════════════

    /**
     * Records a security event.
     *
     * @param action   Short uppercase action code (e.g., "UPLOAD", "LOGIN_FAIL")
     * @param username The user or system actor responsible
     * @param message  Human-readable event details
     */
    public synchronized void log(String action, String username, String message) {
        LogEntry entry = new LogEntry(LocalDateTime.now(), action, username, message);
        inMemoryLog.add(entry);
        writer.println(entry.toFileString(TIMESTAMP_FMT));
    }

    // ══════════════════════ Query API ════════════════════════════

    /**
     * Returns all log entries (intended for Auditor role access).
     *
     * @return Unmodifiable snapshot of current in-memory log
     */
    public List<LogEntry> getAllLogs() {
        return Collections.unmodifiableList(new ArrayList<>(inMemoryLog));
    }

    /**
     * Filters log entries by action type.
     *
     * @param action Action code to filter by (e.g., "LOGIN_FAIL")
     * @return       List of matching log entries
     */
    public List<LogEntry> getLogsByAction(String action) {
        return inMemoryLog.stream()
            .filter(e -> e.action().equalsIgnoreCase(action))
            .toList();
    }

    /**
     * Returns all security-critical events (failures and denials).
     */
    public List<LogEntry> getSecurityEvents() {
        return inMemoryLog.stream()
            .filter(e -> e.action().contains("FAIL") ||
                         e.action().contains("DENIED") ||
                         e.action().contains("INTEGRITY"))
            .toList();
    }

    // ══════════════════════ Display ══════════════════════════════

    /**
     * Prints the audit log to stdout in a formatted table.
     */
    public void printLogs() {
        System.out.printf("  %-19s  %-20s  %-14s  %s%n",
            "Timestamp", "Action", "User", "Details");
        System.out.println("  " + "─".repeat(80));

        for (LogEntry e : inMemoryLog) {
            System.out.printf("  %-19s  %-20s  %-14s  %s%n",
                e.timestamp().format(TIMESTAMP_FMT),
                truncate(e.action(), 20),
                truncate(e.username(), 14),
                truncate(e.message(), 40));
        }
        System.out.println("  " + "─".repeat(80));
        System.out.println("  Total entries: " + inMemoryLog.size() +
            " | Security events: " + getSecurityEvents().size());
    }

    public void close() {
        writer.flush();
        writer.close();
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max - 2) + "..";
    }

    // ══════════════════════ Log Entry ════════════════════════════

    /**
     * Immutable log record.
     * Using Java 16+ record for concise, value-type semantics.
     */
    public record LogEntry(
        LocalDateTime timestamp,
        String        action,
        String        username,
        String        message
    ) {
        /** Formats entry for the on-disk log file. */
        public String toFileString(DateTimeFormatter fmt) {
            return String.format("[%s] [%-20s] [%-12s] %s",
                timestamp.format(fmt), action, username, message);
        }
    }
}
