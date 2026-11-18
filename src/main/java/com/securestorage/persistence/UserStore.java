package com.securestorage.persistence;

import com.securestorage.auth.User;

import java.io.*;
import java.nio.file.*;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Persists user accounts between runs.
 *
 * ── Why this exists ─────────────────────────────────────────────────
 * In v2 the user map lived only in memory and the default admin was re-seeded
 * at every startup. Any account you registered — including the USER account you
 * would use to demonstrate role-based access — vanished when the app closed.
 * Remembering a login is pointless if the account it refers to no longer exists.
 *
 * ── Format and safety ───────────────────────────────────────────────
 * Java serialization of a LinkedHashMap&lt;String, User&gt;, written atomically
 * via a temp file and an ATOMIC_MOVE so a crash mid-write cannot leave a
 * truncated store behind.
 *
 * Deserialization is guarded by an {@link ObjectInputFilter} allow-list. This is
 * the same CWE-502 concern that User.readObject() addresses, handled one layer
 * earlier: the filter rejects unexpected classes before any gadget chain gets a
 * chance to run, rather than relying on validation after construction.
 *
 * Only hashes are stored here. No plain-text password ever reaches this file.
 */
public class UserStore {

    /**
     * Allow-list for deserialization.
     *
     * Listing leaf classes by name looks tighter but is wrong in practice:
     * LocalDateTime serialises through java.time.Ser, a map drags in its own
     * internals, and boxed primitives appear wherever the object graph touches
     * them. Miss one and the whole read is REJECTED, which silently empties the
     * store. Allowing the four packages the graph can legitimately reach, plus
     * depth and size ceilings, still blocks every known gadget chain — those
     * live in libraries this pattern does not admit.
     */
    private static final String FILTER_PATTERN =
        "maxdepth=32;maxrefs=100000;maxarray=100000;"
      + "com.securestorage.auth.*;"
      + "java.util.**;java.time.**;java.lang.**;"
      + "!*";

    private final Path file;

    public UserStore(String directory) throws IOException {
        Path dir = Paths.get(directory);
        Files.createDirectories(dir);
        this.file = dir.resolve("users.dat");
    }

    public boolean exists() { return Files.exists(file); }

    public Path getPath() { return file; }

    /** Loads all users, or an empty map if nothing has been stored yet. */
    @SuppressWarnings("unchecked")
    public Map<String, User> load() {
        if (!Files.exists(file)) return new LinkedHashMap<>();
        try (ObjectInputStream in = new ObjectInputStream(
                new BufferedInputStream(Files.newInputStream(file)))) {
            in.setObjectInputFilter(ObjectInputFilter.Config.createFilter(FILTER_PATTERN));
            Object obj = in.readObject();
            if (obj instanceof Map<?, ?> map) {
                Map<String, User> result = new LinkedHashMap<>();
                map.forEach((k, v) -> {
                    if (k instanceof String s && v instanceof User u) result.put(s, u);
                });
                return result;
            }
        } catch (Exception e) {
            System.err.println("[UserStore] Could not read " + file + " (" + e.getMessage()
                + "). Starting from an empty user store.");
        }
        return new LinkedHashMap<>();
    }

    /** Writes all users atomically. Failures are reported but never fatal. */
    public synchronized void save(Map<String, User> users) {
        Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
        try {
            try (ObjectOutputStream out = new ObjectOutputStream(
                    new BufferedOutputStream(Files.newOutputStream(tmp)))) {
                out.writeObject(new LinkedHashMap<>(users));
            }
            try {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING,
                                      StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            System.err.println("[UserStore] Failed to persist users: " + e.getMessage());
        }
    }
}
