package com.securestorage.research;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One measured data point from the Encryption Lab.
 *
 * Deliberately generic: each benchmark category (bulk encryption, key
 * establishment, signatures, password hashing) reports a different set of
 * metrics, and forcing them into one fixed schema would mean padding tables
 * with blank columns. The exporter takes the union of keys within a category
 * and writes one CSV per category.
 *
 * Categories are declared as constants rather than an enum so a new benchmark
 * can be added without touching the exporter.
 */
public class BenchmarkResult {

    public static final String CAT_SYMMETRIC    = "symmetric-encryption";
    public static final String CAT_KEY_ESTAB    = "key-establishment";
    public static final String CAT_SIGNATURE    = "digital-signature";
    public static final String CAT_PASSWORD     = "password-hashing";

    private final String category;
    private final String algorithm;
    private final Map<String, Object> metrics = new LinkedHashMap<>();

    public BenchmarkResult(String category, String algorithm) {
        this.category  = category;
        this.algorithm = algorithm;
    }

    /** Adds a metric. Returns this, so calls chain. */
    public BenchmarkResult put(String key, Object value) {
        metrics.put(key, value);
        return this;
    }

    public String getCategory()  { return category; }
    public String getAlgorithm() { return algorithm; }
    public Map<String, Object> getMetrics() { return metrics; }

    public Object get(String key) { return metrics.get(key); }

    /** Numeric accessor for charting. Returns NaN when absent or non-numeric. */
    public double getDouble(String key) {
        Object v = metrics.get(key);
        if (v instanceof Number n) return n.doubleValue();
        try { return Double.parseDouble(String.valueOf(v)); }
        catch (Exception e) { return Double.NaN; }
    }

    @Override
    public String toString() {
        return category + "/" + algorithm + " " + metrics;
    }
}
