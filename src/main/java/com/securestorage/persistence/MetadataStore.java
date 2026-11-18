package com.securestorage.persistence;

import com.securestorage.storage.FileMetadata;

import java.io.*;
import java.nio.file.*;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Persists the encrypted-file index between runs.
 *
 * ── Why this exists ─────────────────────────────────────────────────
 * v2 kept the metadata map in memory only. The .enc files were written to disk
 * correctly, but the index that maps a fileId to its name, owner, path and
 * integrity hash was rebuilt empty at every startup. The practical effect: the
 * File Manager showed nothing after a restart while orphaned ciphertext
 * accumulated in the data directory, and the SHA-256 hash needed to verify a
 * download was gone with it.
 *
 * Same atomic-write and deserialization-filter approach as {@link UserStore}.
 */
public class MetadataStore {

    /** Allow-list for deserialization. See UserStore for why it is package-scoped. */
    private static final String FILTER_PATTERN =
        "maxdepth=32;maxrefs=100000;maxarray=100000;"
      + "com.securestorage.storage.*;"
      + "java.util.**;java.time.**;java.lang.**;"
      + "!*";

    private final Path file;

    public MetadataStore(String directory) throws IOException {
        Path dir = Paths.get(directory);
        Files.createDirectories(dir);
        this.file = dir.resolve("index.dat");
    }

    public Path getPath() { return file; }

    public Map<String, FileMetadata> load() {
        if (!Files.exists(file)) return new LinkedHashMap<>();
        try (ObjectInputStream in = new ObjectInputStream(
                new BufferedInputStream(Files.newInputStream(file)))) {
            in.setObjectInputFilter(ObjectInputFilter.Config.createFilter(FILTER_PATTERN));
            Object obj = in.readObject();
            if (obj instanceof Map<?, ?> map) {
                Map<String, FileMetadata> result = new LinkedHashMap<>();
                map.forEach((k, v) -> {
                    if (k instanceof String s && v instanceof FileMetadata m) result.put(s, m);
                });
                return result;
            }
        } catch (Exception e) {
            System.err.println("[MetadataStore] Could not read " + file + " (" + e.getMessage()
                + "). Starting with an empty index.");
        }
        return new LinkedHashMap<>();
    }

    public synchronized void save(Map<String, FileMetadata> index) {
        Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
        try {
            try (ObjectOutputStream out = new ObjectOutputStream(
                    new BufferedOutputStream(Files.newOutputStream(tmp)))) {
                out.writeObject(new LinkedHashMap<>(index));
            }
            try {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING,
                                      StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            System.err.println("[MetadataStore] Failed to persist index: " + e.getMessage());
        }
    }
}
