package com.securestorage.recovery;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Write-Ahead Log (WAL) for crash-safe file operations.
 *
 * Every file system operation is logged BEFORE it executes:
 *
 *   [timestamp] BEGIN    UPLOAD  <internalId>
 *   [timestamp] COMMIT   UPLOAD  <internalId>   ← only written on success
 *
 *   [timestamp] BEGIN    DELETE  <fileId>
 *   [timestamp] ROLLBACK DELETE  <fileId>        ← written if crash/error
 *
 * Recovery logic:
 *   On startup, scan WAL for any BEGIN without a matching COMMIT.
 *   These represent operations that crashed mid-execution.
 *   The recovery engine can then roll back or retry these operations.
 *
 * Benefits of WAL:
 *  - Atomicity: either full operation or nothing (no partial writes)
 *  - Durability: log is flushed to disk before each state change
 *  - Recoverability: incomplete transactions identified automatically
 *
 * File: {recoveryDir}/transaction.wal
 * Format: ISO timestamp | STATUS | OPERATION | RESOURCE_ID
 */
public class TransactionLog {

    private final Path        walPath;
    private final PrintWriter writer;

    /**
     * @param recoveryDir Directory where transaction.wal will be written
     * @throws IOException if directory/file cannot be created
     */
    public TransactionLog(String recoveryDir) throws IOException {
        Files.createDirectories(Paths.get(recoveryDir));
        this.walPath = Paths.get(recoveryDir, "transaction.wal");
        // append=true, autoFlush=true — critical for durability
        this.writer  = new PrintWriter(new FileWriter(walPath.toFile(), true), true);
    }

    // ══════════════════════ WAL Writes ═══════════════════════════

    /**
     * Logs the beginning of an operation.
     * Called BEFORE the operation executes.
     *
     * @param operation  "UPLOAD", "DELETE", etc.
     * @param resourceId Identifier of the affected resource
     */
    public synchronized void logBegin(String operation, String resourceId) {
        writer.printf("%s  BEGIN     %-10s  %s%n", LocalDateTime.now(), operation, resourceId);
    }

    /**
     * Logs successful completion of an operation.
     * Called AFTER the operation succeeds.
     */
    public synchronized void logCommit(String operation, String resourceId) {
        writer.printf("%s  COMMIT    %-10s  %s%n", LocalDateTime.now(), operation, resourceId);
    }

    /**
     * Logs a rollback (crash or error mid-operation).
     * Called in catch blocks.
     */
    public synchronized void logRollback(String operation, String resourceId) {
        writer.printf("%s  ROLLBACK  %-10s  %s%n", LocalDateTime.now(), operation, resourceId);
    }

    // ══════════════════════ Recovery Scan ════════════════════════

    /**
     * Scans the WAL for incomplete transactions.
     *
     * An incomplete transaction has a BEGIN with no matching COMMIT or ROLLBACK.
     * These occurred when the JVM/OS crashed mid-operation.
     *
     * @return List of resource IDs that need rollback/cleanup
     * @throws IOException if WAL file cannot be read
     */
    public List<String> findIncompleteTransactions() throws IOException {
        if (!Files.exists(walPath)) {
            return Collections.emptyList();
        }

        Map<String, String> begun     = new LinkedHashMap<>();  // resourceId → operation
        Set<String>         completed = new HashSet<>();        // resourceIds that finished

        for (String line : Files.readAllLines(walPath)) {
            String[] parts = line.trim().split("\\s+");
            // Expected parts: [date, time, STATUS, OPERATION, resourceId]
            if (parts.length >= 5) {
                String status = parts[2];
                String resId  = parts[4];

                switch (status) {
                    case "BEGIN"    -> begun.put(resId, parts[3]);
                    case "COMMIT",
                         "ROLLBACK" -> completed.add(resId);
                }
            }
        }

        // Incomplete = began but never committed or rolled back
        begun.keySet().removeAll(completed);
        return new ArrayList<>(begun.keySet());
    }

    /**
     * Prints the current WAL contents to stdout.
     */
    public void printWAL() throws IOException {
        if (!Files.exists(walPath)) {
            System.out.println("  [WAL] No transaction log found");
            return;
        }
        System.out.println("  [WAL] Transaction log contents:");
        List<String> lines = Files.readAllLines(walPath);
        lines.forEach(line -> System.out.println("    " + line));
        System.out.println("  [WAL] Total entries: " + lines.size());
    }

    public void close() {
        writer.flush();
        writer.close();
    }
}
