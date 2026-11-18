package com.securestorage.recovery;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Snapshot-based checkpoint manager for system state recovery.
 *
 * Complements the WAL (TransactionLog) with periodic full-state snapshots.
 *
 * Recovery strategy (two-phase):
 *   Phase 1: Load latest checkpoint snapshot  → restores last known good state
 *   Phase 2: Replay WAL from that point       → reapplies committed operations
 *
 * Reliability metrics tracked:
 *   - Checkpoints saved count
 *   - Recovery attempts
 *   - Last checkpoint timestamp
 *   - Estimated RTO (Recovery Time Objective) from save/load times
 *
 * File format: {checkpointDir}/checkpoint_yyyyMMdd_HHmmss.snap (serialized Map)
 * Latest checkpoint = lexicographically last filename (timestamp-ordered).
 */
public class CheckpointManager {

    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    private final Path checkpointDir;

    // Reliability metrics
    private int           checkpointsSaved   = 0;
    private int           recoveryAttempts   = 0;
    private LocalDateTime lastCheckpointTime = null;
    private long          lastSaveTimeMs     = 0;

    /**
     * @param checkpointDirPath Directory to store .snap files
     * @throws IOException if directory cannot be created
     */
    public CheckpointManager(String checkpointDirPath) throws IOException {
        this.checkpointDir = Paths.get(checkpointDirPath);
        Files.createDirectories(checkpointDir);
    }

    // ══════════════════════ Save ═════════════════════════════════

    /**
     * Saves a snapshot of the current system state.
     *
     * State map can contain any serializable metadata:
     *   {"fileCount": 5, "userCount": 3, "timestamp": 1234567890}
     *
     * @param state Map of key-value pairs representing current state
     * @throws IOException on I/O failure
     */
    public void saveCheckpoint(Map<String, Object> state) throws IOException {
        String   filename  = "checkpoint_" + LocalDateTime.now().format(FMT) + ".snap";
        Path     snapPath  = checkpointDir.resolve(filename);
        long     start     = System.currentTimeMillis();

        try (ObjectOutputStream oos = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(snapPath.toFile())))) {
            oos.writeObject(new HashMap<>(state)); // defensive copy
        }

        lastSaveTimeMs     = System.currentTimeMillis() - start;
        lastCheckpointTime = LocalDateTime.now();
        checkpointsSaved++;

        System.out.printf("  [CHECKPOINT] Saved: %s (%dms)%n", filename, lastSaveTimeMs);
    }

    // ══════════════════════ Load ══════════════════════════════════

    /**
     * Loads the most recent checkpoint snapshot.
     *
     * Snapshots are sorted by filename (which embeds ISO timestamp),
     * so the lexicographically last file = most recent.
     *
     * @return Restored state map, or empty map if no checkpoint exists
     * @throws Exception on deserialization failure
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> loadLatestCheckpoint() throws Exception {
        File[] snaps = checkpointDir.toFile().listFiles(
            f -> f.getName().startsWith("checkpoint_") && f.getName().endsWith(".snap"));

        if (snaps == null || snaps.length == 0) {
            System.out.println("  [CHECKPOINT] No snapshot found — starting from empty state");
            return new HashMap<>();
        }

        // Sort by filename (timestamp-encoded), take the last (most recent)
        Arrays.sort(snaps, Comparator.comparing(File::getName));
        File   latest    = snaps[snaps.length - 1];
        long   start     = System.currentTimeMillis();
        recoveryAttempts++;

        try (ObjectInputStream ois = new ObjectInputStream(
                new BufferedInputStream(new FileInputStream(latest)))) {
            Map<String, Object> restored = (Map<String, Object>) ois.readObject();
            long loadTime = System.currentTimeMillis() - start;
            System.out.printf("  [CHECKPOINT] Loaded: %s (RTO=%dms)%n",
                latest.getName(), loadTime);
            return restored;
        }
    }

    // ══════════════════════ Metrics ══════════════════════════════

    /**
     * Prints reliability metrics table.
     *
     * Metrics for research report:
     *  - MTTF: requires simulation (see attack module)
     *  - RTO:  measured as checkpoint load time
     *  - RPO:  time between checkpoints (configurable interval)
     */
    public void printMetrics() {
        System.out.println();
        System.out.println("  ┌──────────────────────────────────────────┐");
        System.out.println("  │       CHECKPOINT RELIABILITY METRICS     │");
        System.out.println("  ├──────────────────────────────────────────┤");
        System.out.printf( "  │  Checkpoints saved:    %-18d│%n", checkpointsSaved);
        System.out.printf( "  │  Recovery attempts:    %-18d│%n", recoveryAttempts);
        System.out.printf( "  │  Last save time (RTO): %-15s ms │%n", lastSaveTimeMs);
        System.out.printf( "  │  Last checkpoint:      %-18s│%n",
            lastCheckpointTime != null ? lastCheckpointTime.format(FMT) : "N/A");
        System.out.println("  └──────────────────────────────────────────┘");
    }

    /** Lists all saved snapshot files. */
    public List<String> listCheckpoints() {
        File[] snaps = checkpointDir.toFile().listFiles(
            f -> f.getName().endsWith(".snap"));
        if (snaps == null) return List.of();
        return Arrays.stream(snaps)
            .map(File::getName)
            .sorted()
            .toList();
    }

    public int  getCheckpointsSaved()  { return checkpointsSaved; }
    public int  getRecoveryAttempts()  { return recoveryAttempts; }
}
