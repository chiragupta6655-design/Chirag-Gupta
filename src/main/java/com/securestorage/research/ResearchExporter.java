package com.securestorage.research;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Writes benchmark output to a research-data folder in a form that can go
 * straight into a paper.
 *
 * Layout, under {BASE_DIR}/research-data/ :
 *
 *   run-2026-09-16_143022/
 *       symmetric-encryption.csv    one row per file size
 *       key-establishment.csv       RSA-2048-OAEP vs ML-KEM parameter sets
 *       digital-signature.csv       RSA-PSS, ECDSA, ML-DSA, SLH-DSA
 *       password-hashing.csv        PBKDF2 vs BCrypt
 *       environment.json            JVM, OS, CPU count, heap, provider versions
 *       summary.md                  tables plus the caveats that belong with them
 *   all-runs.csv                    every row from every run, appended
 *
 * ── Why the environment file matters ────────────────────────────────
 * Timings from a JIT-compiled language on a laptop are not reproducible unless
 * the machine and JVM are stated. A reviewer will ask; environment.json answers
 * it without you having to remember what you ran it on.
 *
 * ── Why all-runs.csv exists ─────────────────────────────────────────
 * A single run is one sample. Repeat the benchmark a few times and this file
 * gives you the spread, so you can report a mean with a standard deviation
 * instead of a single number that happened to land where it did.
 */
public class ResearchExporter {

    private static final DateTimeFormatter STAMP =
        DateTimeFormatter.ofPattern("yyyy-MM-dd_HHmmss");

    private final Path root;

    public ResearchExporter(String baseDir) throws IOException {
        this.root = Paths.get(baseDir, "research-data");
        Files.createDirectories(root);
    }

    public Path getRoot() { return root; }

    /**
     * Writes one complete run.
     *
     * @param results all measurements from this run
     * @param notes   free-text context, e.g. iteration count and file sizes used
     * @return        the run directory that was created
     */
    public Path export(List<BenchmarkResult> results, String notes) throws IOException {
        LocalDateTime now = LocalDateTime.now();
        Path runDir = root.resolve("run-" + now.format(STAMP));
        Files.createDirectories(runDir);

        Map<String, List<BenchmarkResult>> byCategory = new LinkedHashMap<>();
        for (BenchmarkResult r : results) {
            byCategory.computeIfAbsent(r.getCategory(), k -> new ArrayList<>()).add(r);
        }

        for (Map.Entry<String, List<BenchmarkResult>> e : byCategory.entrySet()) {
            Files.writeString(runDir.resolve(e.getKey() + ".csv"),
                toCsv(e.getValue()), StandardCharsets.UTF_8);
        }

        Files.writeString(runDir.resolve("environment.json"),
            environmentJson(now), StandardCharsets.UTF_8);
        Files.writeString(runDir.resolve("summary.md"),
            summaryMarkdown(byCategory, now, notes), StandardCharsets.UTF_8);

        appendToAllRuns(results, now);
        return runDir;
    }

    // ── CSV ──────────────────────────────────────────────────────────

    private String toCsv(List<BenchmarkResult> rows) {
        LinkedHashSet<String> columns = new LinkedHashSet<>();
        for (BenchmarkResult r : rows) columns.addAll(r.getMetrics().keySet());

        StringBuilder sb = new StringBuilder();
        sb.append("algorithm");
        for (String c : columns) sb.append(',').append(escape(c));
        sb.append('\n');

        for (BenchmarkResult r : rows) {
            sb.append(escape(r.getAlgorithm()));
            for (String c : columns) {
                Object v = r.get(c);
                sb.append(',').append(v == null ? "" : escape(String.valueOf(v)));
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    private void appendToAllRuns(List<BenchmarkResult> results, LocalDateTime now)
            throws IOException {
        Path all = root.resolve("all-runs.csv");
        boolean fresh = !Files.exists(all);

        StringBuilder sb = new StringBuilder();
        if (fresh) sb.append("timestamp,category,algorithm,metric,value\n");

        String ts = now.toString();
        for (BenchmarkResult r : results) {
            for (Map.Entry<String, Object> m : r.getMetrics().entrySet()) {
                sb.append(escape(ts)).append(',')
                  .append(escape(r.getCategory())).append(',')
                  .append(escape(r.getAlgorithm())).append(',')
                  .append(escape(m.getKey())).append(',')
                  .append(escape(String.valueOf(m.getValue()))).append('\n');
            }
        }
        Files.writeString(all, sb.toString(), StandardCharsets.UTF_8,
            fresh ? StandardOpenOption.CREATE : StandardOpenOption.APPEND);
    }

    private String escape(String s) {
        if (s == null) return "";
        boolean needsQuotes = s.contains(",") || s.contains("\"") || s.contains("\n");
        String out = s.replace("\"", "\"\"");
        return needsQuotes ? "\"" + out + "\"" : out;
    }

    // ── Environment ──────────────────────────────────────────────────

    private String environmentJson(LocalDateTime now) {
        Runtime rt = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder("{\n");
        json(sb, "timestamp",        now.toString());
        json(sb, "javaVersion",      System.getProperty("java.version"));
        json(sb, "javaVendor",       System.getProperty("java.vendor"));
        json(sb, "jvmName",          System.getProperty("java.vm.name"));
        json(sb, "osName",           System.getProperty("os.name"));
        json(sb, "osVersion",        System.getProperty("os.version"));
        json(sb, "osArch",           System.getProperty("os.arch"));
        json(sb, "availableProcessors", String.valueOf(rt.availableProcessors()));
        json(sb, "maxHeapMB",        String.valueOf(rt.maxMemory() / (1024 * 1024)));
        json(sb, "cryptoProviders",  providerList());
        sb.append("  \"note\": \"Timings are wall-clock on a JIT-compiled runtime; ")
          .append("report medians across several runs rather than a single sample.\"\n}");
        return sb.toString();
    }

    private void json(StringBuilder sb, String k, String v) {
        sb.append("  \"").append(k).append("\": \"")
          .append(v == null ? "" : v.replace("\\", "\\\\").replace("\"", "\\\""))
          .append("\",\n");
    }

    private String providerList() {
        StringBuilder sb = new StringBuilder();
        for (java.security.Provider p : java.security.Security.getProviders()) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(p.getName()).append(' ').append(p.getVersionStr());
        }
        return sb.toString();
    }

    // ── Markdown summary ─────────────────────────────────────────────

    private String summaryMarkdown(Map<String, List<BenchmarkResult>> byCategory,
                                   LocalDateTime now, String notes) {
        StringBuilder sb = new StringBuilder();
        sb.append("# SecureVault — Cryptographic Benchmark Run\n\n");
        sb.append("Generated ").append(now).append("\n\n");
        if (notes != null && !notes.isBlank()) sb.append(notes).append("\n\n");

        sb.append("## Environment\n\n");
        sb.append("- Java ").append(System.getProperty("java.version"))
          .append(" (").append(System.getProperty("java.vm.name")).append(")\n");
        sb.append("- ").append(System.getProperty("os.name")).append(' ')
          .append(System.getProperty("os.version")).append(" / ")
          .append(System.getProperty("os.arch")).append('\n');
        sb.append("- ").append(Runtime.getRuntime().availableProcessors())
          .append(" logical processors, ")
          .append(Runtime.getRuntime().maxMemory() / (1024 * 1024))
          .append(" MB max heap\n\n");

        for (Map.Entry<String, List<BenchmarkResult>> e : byCategory.entrySet()) {
            sb.append("## ").append(titleFor(e.getKey())).append("\n\n");
            sb.append(markdownTable(e.getValue())).append('\n');
        }

        sb.append("""
                ## Reading these numbers

                A few things a reviewer will check, so they are worth stating explicitly:

                1. **The categories are not interchangeable.** AES-256-GCM encrypts bulk
                   data. ML-KEM and RSA-OAEP establish a key. ML-DSA and SLH-DSA sign and
                   encrypt nothing. Comparing across categories measures unrelated work.

                2. **Post-quantum is not uniformly slower.** Lattice operations are often
                   faster than RSA-2048 per operation; the cost shows up in key and
                   ciphertext *size*, not always in time. Report both.

                3. **SLH-DSA trades size for assumptions.** Its signatures are one to two
                   orders of magnitude larger than ML-DSA's, and signing is far slower.
                   In exchange it rests only on hash-function security, with no lattice
                   assumption. That is a conservative-fallback argument, not a
                   performance argument.

                4. **JIT warm-up affects the first iterations.** The lab runs several
                   iterations per size for this reason; medians are more stable than means
                   when the first sample is an outlier.

                5. **These are single-machine results.** They characterise this
                   implementation on this hardware, not the algorithms in general.
                """);
        return sb.toString();
    }

    private String titleFor(String category) {
        return switch (category) {
            case BenchmarkResult.CAT_SYMMETRIC -> "Symmetric encryption (bulk data)";
            case BenchmarkResult.CAT_KEY_ESTAB -> "Key establishment (classical vs post-quantum)";
            case BenchmarkResult.CAT_SIGNATURE -> "Digital signatures (classical vs post-quantum)";
            case BenchmarkResult.CAT_PASSWORD  -> "Password hashing";
            default -> category;
        };
    }

    private String markdownTable(List<BenchmarkResult> rows) {
        LinkedHashSet<String> columns = new LinkedHashSet<>();
        for (BenchmarkResult r : rows) columns.addAll(r.getMetrics().keySet());

        StringBuilder sb = new StringBuilder("| algorithm |");
        for (String c : columns) sb.append(' ').append(c).append(" |");
        sb.append("\n|---|");
        for (int i = 0; i < columns.size(); i++) sb.append("---|");
        sb.append('\n');

        for (BenchmarkResult r : rows) {
            sb.append("| ").append(r.getAlgorithm()).append(" |");
            for (String c : columns) {
                Object v = r.get(c);
                sb.append(' ').append(v == null ? "" : v).append(" |");
            }
            sb.append('\n');
        }
        return sb.toString();
    }
}
