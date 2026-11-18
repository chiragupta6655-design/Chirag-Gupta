package com.securestorage.ui.views;

import com.securestorage.auth.PasswordHasher;
import com.securestorage.crypto.*;
import com.securestorage.crypto.pqc.PqcEngine;
import com.securestorage.crypto.pqc.PqcHybridEncryption;
import com.securestorage.research.BenchmarkResult;
import com.securestorage.ui.AppState;
import com.securestorage.ui.Theme;
import com.securestorage.ui.components.UiHelper;
import javafx.application.Platform;
import javafx.collections.*;
import javafx.geometry.*;
import javafx.scene.Node;
import javafx.scene.chart.*;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.effect.DropShadow;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.TextFlow;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

/**
 * Encryption Laboratory — classical vs post-quantum comparison.
 *
 * ── How the comparison is structured, and why ───────────────────────
 * A single leaderboard ranking AES-256-GCM, RSA-2048, ML-KEM, ML-DSA and
 * SLH-DSA against each other would be meaningless: they do different jobs.
 * ML-KEM establishes a key. ML-DSA and SLH-DSA sign. AES encrypts bulk data.
 * A reviewer would flag that immediately.
 *
 * So the lab runs four separate tracks, and only compares within a track:
 *
 *   1. Bulk encryption      AES-256-GCM across file sizes
 *                           (no PQC counterpart — symmetric crypto is already
 *                           quantum-resistant at 256-bit keys; Grover's
 *                           algorithm halves the effective security level,
 *                           which is why 256 rather than 128 is the choice)
 *   2. Key establishment    RSA-2048-OAEP  vs  ML-KEM-512/768/1024
 *   3. Digital signatures   RSA-2048, ECDSA-P256  vs  ML-DSA-44/65/87,
 *                           SLH-DSA-SHA2-128f/128s
 *   4. Password hashing     PBKDF2-SHA256  vs  BCrypt
 *
 * Each track measures time AND size, because the headline finding for
 * post-quantum cryptography is usually about bytes on the wire rather than
 * milliseconds on the clock.
 */
public class EncryptionLabView extends VBox {

    // ── Data models for the tables ───────────────────────────────────

    public static class BulkRow {
        private final String fileSize, throughput, overhead, verified;
        private final double encryptMs, decryptMs;
        BulkRow(String sz, double enc, double dec, double mbps, double oh, boolean ok) {
            fileSize = sz; encryptMs = round(enc); decryptMs = round(dec);
            throughput = String.format("%.1f MB/s", mbps);
            overhead = String.format("%.4f%%", oh);
            verified = ok ? "✓ VERIFIED" : "✗ MISMATCH";
        }
        public String getFileSize()   { return fileSize; }
        public double getEncryptMs()  { return encryptMs; }
        public double getDecryptMs()  { return decryptMs; }
        public String getThroughput() { return throughput; }
        public String getOverhead()   { return overhead; }
        public String getVerified()   { return verified; }
    }

    public static class KeyEstabRow {
        private final String algorithm, family, status;
        private final double keyGenMs, encapsMs, decapsMs;
        private final int    pubKeyBytes, ciphertextBytes;
        KeyEstabRow(String alg, String fam, double kg, double en, double de,
                    int pk, int ct, String st) {
            algorithm = alg; family = fam; keyGenMs = round(kg); encapsMs = round(en);
            decapsMs = round(de); pubKeyBytes = pk; ciphertextBytes = ct; status = st;
        }
        public String getAlgorithm()       { return algorithm; }
        public String getFamily()          { return family; }
        public double getKeyGenMs()        { return keyGenMs; }
        public double getEncapsMs()        { return encapsMs; }
        public double getDecapsMs()        { return decapsMs; }
        public int    getPubKeyBytes()     { return pubKeyBytes; }
        public int    getCiphertextBytes() { return ciphertextBytes; }
        public String getStatus()          { return status; }
    }

    public static class SignatureRow {
        private final String algorithm, family, status;
        private final double keyGenMs, signMs, verifyMs;
        private final int    pubKeyBytes, signatureBytes;
        SignatureRow(String alg, String fam, double kg, double sg, double vf,
                     int pk, int sig, String st) {
            algorithm = alg; family = fam; keyGenMs = round(kg); signMs = round(sg);
            verifyMs = round(vf); pubKeyBytes = pk; signatureBytes = sig; status = st;
        }
        public String getAlgorithm()      { return algorithm; }
        public String getFamily()         { return family; }
        public double getKeyGenMs()       { return keyGenMs; }
        public double getSignMs()         { return signMs; }
        public double getVerifyMs()       { return verifyMs; }
        public int    getPubKeyBytes()    { return pubKeyBytes; }
        public int    getSignatureBytes() { return signatureBytes; }
        public String getStatus()         { return status; }
    }

    public static class HashRow {
        private final String algorithm, attackRate, preview;
        private final double hashMs, verifyMs;
        HashRow(String a, double h, double v, String rate, String prev) {
            algorithm = a; hashMs = round(h); verifyMs = round(v);
            attackRate = rate; preview = prev;
        }
        public String getAlgorithm()  { return algorithm; }
        public double getHashMs()     { return hashMs; }
        public double getVerifyMs()   { return verifyMs; }
        public String getAttackRate() { return attackRate; }
        public String getPreview()    { return preview; }
    }

    private static double round(double v) { return Math.round(v * 1000.0) / 1000.0; }

    // ── State ────────────────────────────────────────────────────────

    private final ObservableList<BulkRow>      bulkData = FXCollections.observableArrayList();
    private final ObservableList<KeyEstabRow>  kemData  = FXCollections.observableArrayList();
    private final ObservableList<SignatureRow> sigData  = FXCollections.observableArrayList();
    private final ObservableList<HashRow>      hashData = FXCollections.observableArrayList();

    private final List<BenchmarkResult> collected = new ArrayList<>();

    private BarChart<String, Number> bulkChart, kemTimeChart, kemSizeChart,
                                     sigTimeChart, sigSizeChart, hashChart;
    private TextFlow                 verdictPane;
    private TextArea    console;
    private ProgressBar progressBar;
    private Label       progressLabel, progressPct, pqcStatusChip;
    private Button      runBtn, exportBtn;
    private Spinner<Integer> iterationSpinner;
    private ComboBox<String> sizeProfileBox;

    private static final long[] SIZES_QUICK  = {1_024L, 10_240L, 102_400L, 1_048_576L};
    private static final String[] LABELS_QUICK = {"1 KB", "10 KB", "100 KB", "1 MB"};
    private static final long[] SIZES_FULL   = {1_024L, 10_240L, 102_400L, 1_048_576L,
                                                10_485_760L, 52_428_800L};
    private static final String[] LABELS_FULL = {"1 KB", "10 KB", "100 KB", "1 MB",
                                                 "10 MB", "50 MB"};

    public EncryptionLabView() {
        super(0);
        setStyle("-fx-background-color: #080c14;");
        PqcEngine.init();
        build();
    }

    // ── Layout ───────────────────────────────────────────────────────

    private void build() {
        TabPane tabs = new TabPane();
        tabs.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);
        tabs.getTabs().addAll(
            new Tab("VERDICT",          buildVerdictTab()),
            new Tab("BULK ENCRYPTION",  buildBulkTab()),
            new Tab("KEY ESTABLISHMENT",buildKemTab()),
            new Tab("SIGNATURES",       buildSignatureTab()),
            new Tab("PASSWORD HASHING", buildHashTab())
        );
        VBox.setVgrow(tabs, Priority.ALWAYS);

        console = UiHelper.consoleArea();
        console.setPrefRowCount(6);

        log("  SECUREVAULT ENCRYPTION LAB — classical vs post-quantum");
        log("  Tracks: bulk encryption · key establishment · signatures · password hashing");
        log("  PQC provider: " + (PqcEngine.isAvailable()
                ? PqcEngine.providerInfo() + " (FIPS 203/204/205 available)"
                : "UNAVAILABLE — " + PqcEngine.unavailableReason()));
        log("  Click  ▶ RUN  to begin. Results export to " + AppState.BASE_DIR + "/research-data");

        VBox main = new VBox(0, buildHeader(), buildControlBar(), tabs, console);
        main.setStyle("-fx-background-color: #080c14;");
        getChildren().add(main);
        VBox.setVgrow(main, Priority.ALWAYS);
    }

    private VBox buildHeader() {
        Label title = new Label("ENCRYPTION LABORATORY");
        title.setStyle("-fx-font-size: 22px; -fx-font-weight: bold; -fx-text-fill: #f0f4f8;"
            + "-fx-font-family: 'Palatino Linotype', serif;");
        DropShadow glow = new DropShadow();
        glow.setColor(Color.web("#f5a623", 0.2)); glow.setRadius(16);
        title.setEffect(glow);

        Label sub = new Label("Classical and post-quantum primitives, measured side by side "
            + "within each functional category");
        sub.setStyle("-fx-text-fill: #7a8fa6; -fx-font-size: 12px;");

        pqcStatusChip = chipLabel(
            PqcEngine.isAvailable() ? "PQC READY" : "PQC UNAVAILABLE",
            PqcEngine.isAvailable() ? Theme.ACCENT_GREEN : Theme.ACCENT_RED);

        HBox chips = new HBox(10,
            chip("AES-256-GCM",   Theme.ACCENT_AMBER),
            chip("RSA-2048-OAEP", Theme.ACCENT_BLUE),
            chip("ML-KEM · FIPS 203",  Theme.ACCENT_PURPLE),
            chip("ML-DSA · FIPS 204",  Theme.ACCENT_PURPLE),
            chip("SLH-DSA · FIPS 205", Theme.ACCENT_PURPLE),
            new HBox(pqcStatusChip));
        chips.setAlignment(Pos.CENTER_LEFT);

        VBox box = new VBox(10, new VBox(5, title, sub), UiHelper.divider(), chips);
        box.setPadding(new Insets(24, 28, 14, 28));
        return box;
    }

    private VBox buildControlBar() {
        runBtn = UiHelper.btnPrimary("▶  RUN");
        runBtn.setOnAction(e -> runBenchmarks());

        exportBtn = UiHelper.btnGhost("⇩  EXPORT RESEARCH DATA");
        exportBtn.setDisable(true);
        exportBtn.setOnAction(e -> exportResults());

        iterationSpinner = new Spinner<>(1, 25, 5);
        iterationSpinner.setPrefWidth(70);
        iterationSpinner.setEditable(true);

        sizeProfileBox = new ComboBox<>();
        sizeProfileBox.getItems().addAll("Quick (1 KB – 1 MB)", "Full (1 KB – 50 MB)");
        sizeProfileBox.setValue("Quick (1 KB – 1 MB)");
        sizeProfileBox.setPrefWidth(180);

        progressBar = new ProgressBar(0);
        progressBar.setPrefWidth(300); progressBar.setPrefHeight(8);

        progressLabel = new Label("READY");
        progressLabel.setStyle("-fx-text-fill: #7a8fa6; -fx-font-size: 11px; -fx-font-family: 'Courier New';");
        progressPct = new Label("0%");
        progressPct.setStyle("-fx-text-fill: #f5a623; -fx-font-size: 12px; -fx-font-family: 'Courier New'; -fx-font-weight: bold;");

        HBox bar = UiHelper.hbox(14,
            runBtn,
            smallLabel("ITERATIONS"), iterationSpinner,
            smallLabel("SIZES"), sizeProfileBox,
            new VBox(4, progressBar, UiHelper.hbox(6, progressLabel, UiHelper.spacer(), progressPct)),
            UiHelper.spacer(),
            exportBtn);
        bar.setPadding(new Insets(12, 28, 12, 28));
        bar.setStyle("-fx-background-color: #0c1221; -fx-border-color: #162338; -fx-border-width: 1 0 1 0;");
        return new VBox(bar);
    }

    // ── Tabs ─────────────────────────────────────────────────────────

    private Node buildVerdictTab() {
        verdictPane = new TextFlow();
        verdictPane.setPadding(new Insets(4));
        setVerdictPlaceholder();
        ScrollPane sp = UiHelper.scrollPane(verdictPane);
        sp.setPadding(new Insets(18, 24, 18, 24));
        return sp;
    }

    private Node buildBulkTab() {
        TableView<BulkRow> table = new TableView<>(bulkData);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        table.setPlaceholder(placeholder("── RUN THE BENCHMARK TO POPULATE ──"));
        addColumns(table,
            "FILE SIZE",     "fileSize",
            "ENCRYPT (ms)",  "encryptMs",
            "DECRYPT (ms)",  "decryptMs",
            "THROUGHPUT",    "throughput",
            "SIZE OVERHEAD", "overhead",
            "ROUND-TRIP",    "verified");
        table.setPrefHeight(220);

        bulkChart = barChart("AES-256-GCM throughput by file size", "File size", "MB/s");

        return tabBody(table, bulkChart,
            "AES-256-GCM has no post-quantum replacement in this table because it does not "
          + "need one. Grover's algorithm gives at best a quadratic speed-up against a "
          + "symmetric cipher, so a 256-bit key retains roughly 128 bits of security against "
          + "a quantum adversary — which is why the design uses AES-256 rather than AES-128. "
          + "Overhead here is the 12-byte IV plus the 16-byte GCM tag plus the wrapped key.");
    }

    private Node buildKemTab() {
        TableView<KeyEstabRow> table = new TableView<>(kemData);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        table.setPlaceholder(placeholder("── RUN THE BENCHMARK TO POPULATE ──"));
        addColumns(table,
            "ALGORITHM",             "algorithm",
            "FAMILY",                "family",
            "KEYGEN (ms)",           "keyGenMs",
            "WRAP/ENCAPS (ms)",      "encapsMs",
            "UNWRAP/DECAPS (ms)",    "decapsMs",
            "PUBKEY (B)",            "pubKeyBytes",
            "CIPHERTEXT (B)",        "ciphertextBytes",
            "STATUS",                "status");
        table.setPrefHeight(200);

        kemTimeChart = barChart("Key establishment — time per operation", "Algorithm", "milliseconds");
        kemSizeChart = barChart("Key establishment — bytes on the wire",  "Algorithm", "bytes");

        HBox charts = new HBox(12, kemTimeChart, kemSizeChart);
        HBox.setHgrow(kemTimeChart, Priority.ALWAYS);
        HBox.setHgrow(kemSizeChart, Priority.ALWAYS);

        return tabBody(table, charts,
            "This is the fair fight: both columns solve the same problem, which is getting a "
          + "symmetric key to the recipient. RSA transports a key you chose; a KEM derives one "
          + "neither side picked, which is why KEMs have no padding-oracle attack surface. "
          + "Expect ML-KEM to win on time and lose on size — its ciphertext is around 1,088 "
          + "bytes at the level-3 parameter set against RSA-2048's 256, and that penalty is "
          + "per file, so it matters for many small files and disappears for a few large ones.");
    }

    private Node buildSignatureTab() {
        TableView<SignatureRow> table = new TableView<>(sigData);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        table.setPlaceholder(placeholder("── RUN THE BENCHMARK TO POPULATE ──"));
        addColumns(table,
            "ALGORITHM",     "algorithm",
            "FAMILY",        "family",
            "KEYGEN (ms)",   "keyGenMs",
            "SIGN (ms)",     "signMs",
            "VERIFY (ms)",   "verifyMs",
            "PUBKEY (B)",    "pubKeyBytes",
            "SIGNATURE (B)", "signatureBytes",
            "STATUS",        "status");
        table.setPrefHeight(230);

        sigTimeChart = barChart("Signatures — sign and verify time", "Algorithm", "milliseconds");
        sigSizeChart = barChart("Signatures — signature size",       "Algorithm", "bytes");

        HBox charts = new HBox(12, sigTimeChart, sigSizeChart);
        HBox.setHgrow(sigTimeChart, Priority.ALWAYS);
        HBox.setHgrow(sigSizeChart, Priority.ALWAYS);

        return tabBody(table, charts,
            "SLH-DSA is the outlier and that is the point of including it. Its signatures run "
          + "to several kilobytes and signing is orders of magnitude slower than ML-DSA. What "
          + "it buys is a security argument that rests on nothing but the underlying hash "
          + "function — no lattice assumption at all. It is the conservative fallback if "
          + "lattice cryptanalysis ever advances, not a performance option.");
    }

    private Node buildHashTab() {
        TableView<HashRow> table = new TableView<>(hashData);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        table.setPlaceholder(placeholder("── RUN THE BENCHMARK TO POPULATE ──"));
        addColumns(table,
            "ALGORITHM",   "algorithm",
            "HASH (ms)",   "hashMs",
            "VERIFY (ms)", "verifyMs",
            "ATTACK RATE", "attackRate",
            "STORED FORM", "preview");
        table.setPrefHeight(180);

        hashChart = barChart("Password hashing — cost per attempt", "Algorithm", "milliseconds");

        return tabBody(table, hashChart,
            "Here a higher number is the better result. Both algorithms are deliberately slow; "
          + "the metric that matters is how many guesses per second an attacker with a stolen "
          + "hash database can make. Neither is affected by quantum computing in any "
          + "interesting way — Grover's algorithm applies, but an attacker's real constraint "
          + "is the iteration count, not the hardware.");
    }

    private Node tabBody(Node table, Node charts, String note) {
        Label lbl = new Label(note);
        lbl.setStyle("-fx-text-fill: #7a8fa6; -fx-font-size: 11px;");
        lbl.setWrapText(true);

        VBox box = new VBox(12, table, charts, lbl);
        box.setPadding(new Insets(14));
        VBox.setVgrow(charts, Priority.ALWAYS);
        ScrollPane sp = UiHelper.scrollPane(box);
        return sp;
    }

    // ── Benchmark execution ──────────────────────────────────────────

    private void runBenchmarks() {
        runBtn.setDisable(true);
        exportBtn.setDisable(true);
        bulkData.clear(); kemData.clear(); sigData.clear(); hashData.clear();
        collected.clear();
        clearCharts();
        console.clear();
        setVerdictPlaceholder();

        final int  iterations = iterationSpinner.getValue();
        final boolean full    = sizeProfileBox.getValue().startsWith("Full");

        Thread worker = new Thread(() -> {
            try {
                log("  Running " + iterations + " iteration(s) per measurement. "
                    + "Medians are reported.");
                runBulkTrack(iterations, full);
                runKeyEstablishmentTrack(iterations);
                runSignatureTrack(iterations);
                runPasswordTrack();
                Platform.runLater(this::renderVerdict);
                setProgress(1.0, "COMPLETE", "100%");
                log("\n  ✓  All tracks complete. Use EXPORT RESEARCH DATA to write CSV/JSON/Markdown.");
                Platform.runLater(() -> exportBtn.setDisable(false));
            } catch (OutOfMemoryError oom) {
                log("  ✗  Out of memory. Use the Quick size profile, or raise -Xmx.");
                setProgress(0, "OUT OF MEMORY", "ERR");
            } catch (Exception ex) {
                log("  ✗  Error: " + ex);
                setProgress(0, "ERROR", "ERR");
            } finally {
                Platform.runLater(() -> runBtn.setDisable(false));
            }
        }, "benchmark-worker");
        worker.setDaemon(true);
        worker.start();
    }

    // Track 1 — bulk symmetric encryption
    private void runBulkTrack(int iterations, boolean full) throws Exception {
        long[]   sizes  = full ? SIZES_FULL  : SIZES_QUICK;
        String[] labels = full ? LABELS_FULL : LABELS_QUICK;

        setProgress(0.02, "GENERATING RSA-2048 KEY PAIR…", "2%");
        RSAEncryption rsa = new RSAEncryption();
        KeyPair rsaKp = rsa.generateKeyPair();
        HybridEncryption hybrid = new HybridEncryption();
        SecureRandom rand = new SecureRandom();

        log("\n  ── TRACK 1: BULK ENCRYPTION (AES-256-GCM) ──");

        XYChart.Series<String, Number> series = new XYChart.Series<>();
        series.setName("Throughput MB/s");

        for (int i = 0; i < sizes.length; i++) {
            long size = sizes[i];
            String label = labels[i];
            double pct = 0.03 + 0.25 * ((i + 1.0) / sizes.length);
            setProgress(pct, "BULK: " + label + "…", pctText(pct));

            byte[] plain = new byte[(int) size];
            rand.nextBytes(plain);

            List<Double> encTimes = new ArrayList<>(), decTimes = new ArrayList<>();
            boolean ok = true;
            EncryptedPackage pkg = null;

            for (int it = 0; it < iterations; it++) {
                long t0 = System.nanoTime();
                pkg = hybrid.encrypt(plain, rsaKp.getPublic());
                encTimes.add(msSince(t0));

                long t1 = System.nanoTime();
                byte[] out = hybrid.decrypt(pkg, rsaKp.getPrivate());
                decTimes.add(msSince(t1));

                ok &= Arrays.equals(plain, out);
            }

            double encMs = median(encTimes), decMs = median(decTimes);
            double mbps  = encMs > 0 ? (size / 1_048_576.0) / (encMs / 1000.0) : 0;
            double oh    = 100.0 * (pkg.getTotalSizeBytes() - size) / size;

            BulkRow row = new BulkRow(label, encMs, decMs, mbps, oh, ok);
            Platform.runLater(() -> bulkData.add(row));
            series.getData().add(new XYChart.Data<>(label, mbps));

            collected.add(new BenchmarkResult(BenchmarkResult.CAT_SYMMETRIC, "AES-256-GCM")
                .put("file_size_bytes", size)
                .put("file_size_label", label)
                .put("iterations", iterations)
                .put("encrypt_ms_median", round(encMs))
                .put("decrypt_ms_median", round(decMs))
                .put("encrypt_ms_min", round(Collections.min(encTimes)))
                .put("encrypt_ms_max", round(Collections.max(encTimes)))
                .put("throughput_mb_per_s", round(mbps))
                .put("size_overhead_percent", round(oh))
                .put("round_trip_ok", ok));

            log(String.format("  %-8s enc=%.2fms  dec=%.2fms  %.1f MB/s  overhead=%.4f%%  %s",
                label, encMs, decMs, mbps, oh, ok ? "OK" : "FAIL"));
        }
        Platform.runLater(() -> bulkChart.getData().setAll(series));
    }

    // Track 2 — key establishment
    private void runKeyEstablishmentTrack(int iterations) {
        log("\n  ── TRACK 2: KEY ESTABLISHMENT (RSA-OAEP vs ML-KEM) ──");
        setProgress(0.32, "KEY ESTABLISHMENT…", "32%");

        XYChart.Series<String, Number> wrapS   = new XYChart.Series<>();
        XYChart.Series<String, Number> unwrapS = new XYChart.Series<>();
        XYChart.Series<String, Number> pkS     = new XYChart.Series<>();
        XYChart.Series<String, Number> ctS     = new XYChart.Series<>();
        wrapS.setName("wrap / encapsulate");
        unwrapS.setName("unwrap / decapsulate");
        pkS.setName("public key");
        ctS.setName("ciphertext");

        // RSA-2048-OAEP baseline
        try {
            RSAEncryption rsa = new RSAEncryption();
            AESEncryption aes = new AESEncryption();

            List<Double> kg = new ArrayList<>(), wr = new ArrayList<>(), un = new ArrayList<>();
            int pkLen = 0, ctLen = 0;
            boolean ok = true;

            for (int i = 0; i < iterations; i++) {
                long t0 = System.nanoTime();
                KeyPair kp = rsa.generateKeyPair();
                kg.add(msSince(t0));

                SecretKey aesKey = aes.generateKey();
                byte[] raw = aesKey.getEncoded();

                long t1 = System.nanoTime();
                byte[] wrapped = rsa.encrypt(raw, kp.getPublic());
                wr.add(msSince(t1));

                long t2 = System.nanoTime();
                byte[] unwrapped = rsa.decrypt(wrapped, kp.getPrivate());
                un.add(msSince(t2));

                ok &= Arrays.equals(raw, unwrapped);
                pkLen = kp.getPublic().getEncoded().length;
                ctLen = wrapped.length;
            }

            addKemRow("RSA-2048-OAEP-SHA256", "Classical (factoring)",
                median(kg), median(wr), median(un), pkLen, ctLen,
                ok ? "✓ OK" : "✗ FAIL", wrapS, unwrapS, pkS, ctS, iterations);
        } catch (Exception e) {
            log("  ✗  RSA baseline failed: " + e.getMessage());
        }

        // ML-KEM parameter sets
        if (!PqcEngine.isAvailable()) {
            log("  ⚠  ML-KEM skipped — " + PqcEngine.unavailableReason());
            Platform.runLater(() -> kemData.add(new KeyEstabRow(
                "ML-KEM (FIPS 203)", "Post-quantum (lattice)", 0, 0, 0, 0, 0, "UNAVAILABLE")));
        } else {
            for (PqcEngine.Kem set : PqcEngine.Kem.values()) {
                try {
                    List<Double> kg = new ArrayList<>(), en = new ArrayList<>(), de = new ArrayList<>();
                    int pkLen = 0, ctLen = 0;
                    boolean ok = true;

                    for (int i = 0; i < iterations; i++) {
                        long t0 = System.nanoTime();
                        KeyPair kp = PqcEngine.generateKemKeyPair(set);
                        kg.add(msSince(t0));

                        long t1 = System.nanoTime();
                        PqcEngine.Encapsulation enc = PqcEngine.encapsulate(kp.getPublic());
                        en.add(msSince(t1));

                        long t2 = System.nanoTime();
                        byte[] recovered = PqcEngine.decapsulate(kp.getPrivate(), enc.ciphertext());
                        de.add(msSince(t2));

                        ok &= Arrays.equals(enc.sharedSecret(), recovered);
                        pkLen = kp.getPublic().getEncoded().length;
                        ctLen = enc.ciphertext().length;
                    }

                    addKemRow(set.displayName, "Post-quantum (lattice, cat " + set.nistCategory + ")",
                        median(kg), median(en), median(de), pkLen, ctLen,
                        ok ? "✓ OK" : "✗ FAIL", wrapS, unwrapS, pkS, ctS, iterations);
                } catch (Exception e) {
                    log("  ✗  " + set.displayName + " failed: " + e.getMessage());
                    Platform.runLater(() -> kemData.add(new KeyEstabRow(
                        set.displayName, "Post-quantum (lattice)", 0, 0, 0, 0, 0, "ERROR")));
                }
            }
        }

        Platform.runLater(() -> {
            kemTimeChart.getData().setAll(wrapS, unwrapS);
            kemSizeChart.getData().setAll(pkS, ctS);
        });
    }

    private void addKemRow(String name, String family, double kg, double enc, double dec,
                           int pkLen, int ctLen, String status,
                           XYChart.Series<String, Number> wrapS,
                           XYChart.Series<String, Number> unwrapS,
                           XYChart.Series<String, Number> pkS,
                           XYChart.Series<String, Number> ctS,
                           int iterations) {
        KeyEstabRow row = new KeyEstabRow(name, family, kg, enc, dec, pkLen, ctLen, status);
        Platform.runLater(() -> kemData.add(row));

        String shortName = name.replace("-SHA256", "");
        wrapS.getData().add(new XYChart.Data<>(shortName, enc));
        unwrapS.getData().add(new XYChart.Data<>(shortName, dec));
        pkS.getData().add(new XYChart.Data<>(shortName, pkLen));
        ctS.getData().add(new XYChart.Data<>(shortName, ctLen));

        collected.add(new BenchmarkResult(BenchmarkResult.CAT_KEY_ESTAB, name)
            .put("family", family)
            .put("iterations", iterations)
            .put("keygen_ms_median", round(kg))
            .put("encapsulate_or_wrap_ms_median", round(enc))
            .put("decapsulate_or_unwrap_ms_median", round(dec))
            .put("public_key_bytes", pkLen)
            .put("ciphertext_bytes", ctLen)
            .put("status", status));

        log(String.format("  %-24s keygen=%.2fms  wrap=%.3fms  unwrap=%.3fms  pk=%dB  ct=%dB",
            name, kg, enc, dec, pkLen, ctLen));
    }

    // Track 3 — signatures
    private void runSignatureTrack(int iterations) {
        log("\n  ── TRACK 3: DIGITAL SIGNATURES ──");
        setProgress(0.55, "SIGNATURES…", "55%");

        byte[] message = ("SecureVault benchmark message — "
            + "a fixed 64-byte payload for fair signing.").getBytes(StandardCharsets.UTF_8);

        XYChart.Series<String, Number> signS   = new XYChart.Series<>();
        XYChart.Series<String, Number> verifyS = new XYChart.Series<>();
        XYChart.Series<String, Number> sizeS   = new XYChart.Series<>();
        signS.setName("sign");
        verifyS.setName("verify");
        sizeS.setName("signature bytes");

        // Classical baselines from the JDK.
        benchClassicalSignature("RSA-2048 PKCS#1v1.5-SHA256", "Classical (factoring)",
            "RSA", 2048, "SHA256withRSA", message, iterations, signS, verifyS, sizeS);
        benchClassicalSignature("ECDSA-P256-SHA256", "Classical (elliptic curve)",
            "EC", 256, "SHA256withECDSA", message, iterations, signS, verifyS, sizeS);

        if (!PqcEngine.isAvailable()) {
            log("  ⚠  ML-DSA and SLH-DSA skipped — " + PqcEngine.unavailableReason());
            Platform.runLater(() -> {
                sigData.add(new SignatureRow("ML-DSA (FIPS 204)",
                    "Post-quantum (lattice)", 0, 0, 0, 0, 0, "UNAVAILABLE"));
                sigData.add(new SignatureRow("SLH-DSA (FIPS 205)",
                    "Post-quantum (hash-based)", 0, 0, 0, 0, 0, "UNAVAILABLE"));
            });
        } else {
            for (PqcEngine.Sig set : PqcEngine.Sig.values()) {
                try {
                    List<Double> kg = new ArrayList<>(), sg = new ArrayList<>(), vf = new ArrayList<>();
                    int pkLen = 0, sigLen = 0;
                    boolean ok = true;

                    for (int i = 0; i < iterations; i++) {
                        long t0 = System.nanoTime();
                        KeyPair kp = PqcEngine.generateSigKeyPair(set);
                        kg.add(msSince(t0));

                        long t1 = System.nanoTime();
                        byte[] sig = PqcEngine.sign(kp.getPrivate(), message, set);
                        sg.add(msSince(t1));

                        long t2 = System.nanoTime();
                        boolean valid = PqcEngine.verify(kp.getPublic(), message, sig, set);
                        vf.add(msSince(t2));

                        ok &= valid;
                        pkLen  = kp.getPublic().getEncoded().length;
                        sigLen = sig.length;
                    }

                    String family = set.isHashBased()
                        ? "Post-quantum (hash-based, cat " + set.nistCategory + ")"
                        : "Post-quantum (lattice, cat " + set.nistCategory + ")";

                    addSignatureRow(set.displayName, family, median(kg), median(sg), median(vf),
                        pkLen, sigLen, ok ? "✓ OK" : "✗ FAIL", signS, verifyS, sizeS, iterations);
                } catch (Exception e) {
                    log("  ✗  " + set.displayName + " failed: " + e.getMessage());
                    Platform.runLater(() -> sigData.add(new SignatureRow(
                        set.displayName, set.standard, 0, 0, 0, 0, 0, "ERROR")));
                }
            }
        }

        Platform.runLater(() -> {
            sigTimeChart.getData().setAll(signS, verifyS);
            sigSizeChart.getData().setAll(sizeS);
        });
    }

    private void benchClassicalSignature(String display, String family, String keyAlg,
                                         int keySize, String sigAlg, byte[] message,
                                         int iterations,
                                         XYChart.Series<String, Number> signS,
                                         XYChart.Series<String, Number> verifyS,
                                         XYChart.Series<String, Number> sizeS) {
        try {
            List<Double> kg = new ArrayList<>(), sg = new ArrayList<>(), vf = new ArrayList<>();
            int pkLen = 0, sigLen = 0;
            boolean ok = true;

            for (int i = 0; i < iterations; i++) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlg);
                if ("EC".equals(keyAlg)) kpg.initialize(new ECGenParameterSpec("secp256r1"));
                else kpg.initialize(keySize);

                long t0 = System.nanoTime();
                KeyPair kp = kpg.generateKeyPair();
                kg.add(msSince(t0));

                Signature signer = Signature.getInstance(sigAlg);
                signer.initSign(kp.getPrivate());
                signer.update(message);
                long t1 = System.nanoTime();
                byte[] sig = signer.sign();
                sg.add(msSince(t1));

                Signature verifier = Signature.getInstance(sigAlg);
                verifier.initVerify(kp.getPublic());
                verifier.update(message);
                long t2 = System.nanoTime();
                boolean valid = verifier.verify(sig);
                vf.add(msSince(t2));

                ok &= valid;
                pkLen  = kp.getPublic().getEncoded().length;
                sigLen = sig.length;
            }

            addSignatureRow(display, family, median(kg), median(sg), median(vf),
                pkLen, sigLen, ok ? "✓ OK" : "✗ FAIL", signS, verifyS, sizeS, iterations);
        } catch (Exception e) {
            log("  ✗  " + display + " failed: " + e.getMessage());
        }
    }

    private void addSignatureRow(String name, String family, double kg, double sg, double vf,
                                 int pkLen, int sigLen, String status,
                                 XYChart.Series<String, Number> signS,
                                 XYChart.Series<String, Number> verifyS,
                                 XYChart.Series<String, Number> sizeS,
                                 int iterations) {
        SignatureRow row = new SignatureRow(name, family, kg, sg, vf, pkLen, sigLen, status);
        Platform.runLater(() -> sigData.add(row));

        String shortName = name.split(" ")[0];
        signS.getData().add(new XYChart.Data<>(shortName, sg));
        verifyS.getData().add(new XYChart.Data<>(shortName, vf));
        sizeS.getData().add(new XYChart.Data<>(shortName, sigLen));

        collected.add(new BenchmarkResult(BenchmarkResult.CAT_SIGNATURE, name)
            .put("family", family)
            .put("iterations", iterations)
            .put("keygen_ms_median", round(kg))
            .put("sign_ms_median", round(sg))
            .put("verify_ms_median", round(vf))
            .put("public_key_bytes", pkLen)
            .put("signature_bytes", sigLen)
            .put("status", status));

        log(String.format("  %-22s keygen=%.2fms  sign=%.3fms  verify=%.3fms  pk=%dB  sig=%dB",
            name, kg, sg, vf, pkLen, sigLen));
    }

    // Track 4 — password hashing
    private void runPasswordTrack() {
        log("\n  ── TRACK 4: PASSWORD HASHING ──");
        setProgress(0.85, "PASSWORD HASHING…", "85%");

        PasswordHasher hasher = new PasswordHasher();
        String pw = "Bench@Pass1!";

        XYChart.Series<String, Number> hashS   = new XYChart.Series<>();
        XYChart.Series<String, Number> verifyS = new XYChart.Series<>();
        hashS.setName("hash");
        verifyS.setName("verify");

        for (PasswordHasher.Algorithm alg : PasswordHasher.Algorithm.values()) {
            long t0 = System.nanoTime();
            String stored = hasher.hash(pw, alg);
            double hashMs = msSince(t0);

            long t1 = System.nanoTime();
            boolean ok = hasher.verify(pw, stored);
            double verifyMs = msSince(t1);

            long rate = hashMs > 0 ? Math.round(1000.0 / hashMs) : 0;
            String preview = stored.length() > 34 ? stored.substring(0, 34) + "…" : stored;

            HashRow row = new HashRow(alg.name(), hashMs, verifyMs,
                "~" + rate + " guesses/sec" + (ok ? "" : " (VERIFY FAILED)"), preview);
            Platform.runLater(() -> hashData.add(row));

            hashS.getData().add(new XYChart.Data<>(alg.name(), hashMs));
            verifyS.getData().add(new XYChart.Data<>(alg.name(), verifyMs));

            collected.add(new BenchmarkResult(BenchmarkResult.CAT_PASSWORD, alg.name())
                .put("parameters", PasswordHasher.describe(alg))
                .put("hash_ms", round(hashMs))
                .put("verify_ms", round(verifyMs))
                .put("est_guesses_per_second", rate)
                .put("verify_ok", ok));

            log(String.format("  %-8s hash=%.1fms  verify=%.1fms  ~%d guesses/sec",
                alg.name(), hashMs, verifyMs, rate));
        }
        Platform.runLater(() -> hashChart.getData().setAll(hashS, verifyS));
    }

    // ── Verdict ──────────────────────────────────────────────────────

    private void setVerdictPlaceholder() {
        verdictPane.getChildren().setAll(
            body("Run the benchmark to generate a comparison. This tab summarises which "
               + "algorithm wins in each category and, more usefully for a paper, why the "
               + "answer is not the same for every workload.\n"));
    }

    /**
     * Builds a written comparison from the measured data.
     *
     * The wording is deliberately conditional on what was actually measured. A
     * summary that asserts a winner regardless of the numbers is worse than no
     * summary, because it will eventually contradict the table above it.
     */
    private void renderVerdict() {
        List<Node> out = new ArrayList<>();
        out.add(heading("Which is better?\n"));
        out.add(body("Short answer: it depends on the job, and the honest version of that "
            + "sentence is what belongs in the paper.\n\n"));

        // Key establishment
        out.add(subheading("Key establishment\n"));
        KeyEstabRow rsa = findKem("RSA");
        KeyEstabRow mlkem = findKem("ML-KEM-768");
        if (rsa != null && mlkem != null && !"UNAVAILABLE".equals(mlkem.getStatus())) {
            double wrapRatio = safeRatio(rsa.getEncapsMs(), mlkem.getEncapsMs());
            double sizeRatio = safeRatio(mlkem.getCiphertextBytes(), rsa.getCiphertextBytes());
            out.add(body(String.format(
                "ML-KEM-768 encapsulated in %.3f ms against RSA-2048-OAEP's %.3f ms — "
                + "%s. Key generation is the larger gap: %.2f ms versus %.2f ms, because RSA "
                + "has to search for primes while a lattice key is essentially sampled. "
                + "The cost lands on size: %d bytes of ciphertext against %d, a %.1fx increase "
                + "that is charged per encapsulation.\n\n",
                mlkem.getEncapsMs(), rsa.getEncapsMs(),
                wrapRatio >= 1 ? String.format("%.1fx faster", wrapRatio)
                               : String.format("%.1fx slower", 1 / wrapRatio),
                mlkem.getKeyGenMs(), rsa.getKeyGenMs(),
                mlkem.getCiphertextBytes(), rsa.getCiphertextBytes(), sizeRatio)));
            out.add(body("For this application — one key encapsulation per stored file — "
                + "ML-KEM wins. The extra bytes are a fixed per-file cost that is invisible "
                + "next to the file itself, and it removes the long-term exposure of anything "
                + "archived today being decrypted later.\n\n"));
        } else {
            out.add(body("ML-KEM results are unavailable, so no comparison can be drawn. "
                + "Check that bcprov-jdk18on 1.80 or newer is on the classpath.\n\n"));
        }

        // Signatures
        out.add(subheading("Digital signatures\n"));
        SignatureRow ecdsa = findSig("ECDSA");
        SignatureRow mldsa = findSig("ML-DSA-65");
        SignatureRow slh   = findSigContaining("SLH-DSA");
        if (ecdsa != null && mldsa != null && !"UNAVAILABLE".equals(mldsa.getStatus())) {
            out.add(body(String.format(
                "ML-DSA-65 signed in %.3f ms and verified in %.3f ms, against ECDSA-P256's "
                + "%.3f ms and %.3f ms. Signature size is where the trade sits: %d bytes "
                + "against %d, roughly %.0fx.\n",
                mldsa.getSignMs(), mldsa.getVerifyMs(),
                ecdsa.getSignMs(), ecdsa.getVerifyMs(),
                mldsa.getSignatureBytes(), ecdsa.getSignatureBytes(),
                safeRatio(mldsa.getSignatureBytes(), ecdsa.getSignatureBytes()))));
        }
        if (slh != null && !"UNAVAILABLE".equals(slh.getStatus()) && mldsa != null) {
            out.add(body(String.format(
                "SLH-DSA is the deliberate outlier: %d-byte signatures and %.2f ms to sign, "
                + "against ML-DSA-65's %d bytes and %.3f ms. It is not competing on "
                + "performance. Its security rests on hash functions alone, with no lattice "
                + "assumption, which makes it the fallback if lattice cryptanalysis advances.\n\n",
                slh.getSignatureBytes(), slh.getSignMs(),
                mldsa.getSignatureBytes(), mldsa.getSignMs())));
        } else {
            out.add(body("\n"));
        }

        // Bulk + password
        out.add(subheading("Bulk encryption and password hashing\n"));
        out.add(body("Neither of these changes in a post-quantum world in the way people "
            + "often assume. AES-256 keeps roughly 128 bits of security against Grover's "
            + "algorithm, so it stays. PBKDF2 and BCrypt are constrained by their iteration "
            + "counts, not by the attacker's hardware generation.\n\n"));

        out.add(subheading("What to claim, and what not to\n"));
        out.add(body("These numbers characterise this implementation on this machine. "
            + "They do not establish that one algorithm is faster than another in general — "
            + "Bouncy Castle's Java implementations are not equally optimised across "
            + "primitives, and the JDK's RSA is native while ML-KEM is not. "
            + "State that limitation explicitly; it is the first thing a reviewer will look "
            + "for, and acknowledging it is stronger than having it pointed out.\n"));

        verdictPane.getChildren().setAll(out);
    }

    private KeyEstabRow findKem(String prefix) {
        return kemData.stream().filter(r -> r.getAlgorithm().startsWith(prefix)).findFirst().orElse(null);
    }
    private SignatureRow findSig(String prefix) {
        return sigData.stream().filter(r -> r.getAlgorithm().startsWith(prefix)).findFirst().orElse(null);
    }
    private SignatureRow findSigContaining(String s) {
        return sigData.stream().filter(r -> r.getAlgorithm().contains(s)
            && !"UNAVAILABLE".equals(r.getStatus())).findFirst().orElse(null);
    }
    private double safeRatio(double a, double b) {
        return (b == 0 || Double.isNaN(b)) ? Double.NaN : a / b;
    }

    // ── Export ───────────────────────────────────────────────────────

    private void exportResults() {
        try {
            String notes = "Iterations per measurement: " + iterationSpinner.getValue()
                + ". Size profile: " + sizeProfileBox.getValue()
                + ". PQC provider: " + (PqcEngine.isAvailable()
                    ? PqcEngine.providerInfo() : "unavailable")
                + ".";
            Path dir = AppState.get().getResearchExporter().export(collected, notes);
            log("\n  ✓  Exported " + collected.size() + " measurements to:");
            log("     " + dir.toAbsolutePath());
            log("     Files: symmetric-encryption.csv, key-establishment.csv, "
                + "digital-signature.csv, password-hashing.csv, environment.json, summary.md");

            Alert a = new Alert(Alert.AlertType.INFORMATION);
            a.setTitle("Research data exported");
            a.setHeaderText("Saved " + collected.size() + " measurements");
            a.setContentText(dir.toAbsolutePath() + "\n\n"
                + "Per-category CSVs, an environment.json describing the machine and JVM, "
                + "and a summary.md you can paste into a draft. Repeat runs append to "
                + "all-runs.csv so you can report a spread rather than a single sample.");
            a.getDialogPane().setMinWidth(560);
            a.showAndWait();
        } catch (Exception e) {
            log("  ✗  Export failed: " + e.getMessage());
        }
    }

    // ── Small UI helpers ─────────────────────────────────────────────

    private BarChart<String, Number> barChart(String title, String xLabel, String yLabel) {
        CategoryAxis x = new CategoryAxis();
        x.setLabel(xLabel);
        NumberAxis y = new NumberAxis();
        y.setLabel(yLabel);

        BarChart<String, Number> chart = new BarChart<>(x, y);
        chart.setTitle(title);
        chart.setAnimated(false);
        chart.setLegendVisible(true);
        chart.setPrefHeight(300);
        chart.setMinHeight(240);
        chart.setStyle("-fx-background-color: #0c1221; -fx-text-fill: #f0f4f8;");
        return chart;
    }

    private void clearCharts() {
        Platform.runLater(() -> {
            bulkChart.getData().clear();
            kemTimeChart.getData().clear();
            kemSizeChart.getData().clear();
            sigTimeChart.getData().clear();
            sigSizeChart.getData().clear();
            hashChart.getData().clear();
        });
    }

    /**
     * Adds columns from alternating header/property pairs.
     *
     * Building the TableColumn inside a method that already knows the row type
     * avoids asking the compiler to infer a type argument from a wildcard
     * target, which is where the generic version of this helper tends to go
     * wrong.
     */
    private static <S> void addColumns(TableView<S> table, String... headerPropertyPairs) {
        for (int i = 0; i + 1 < headerPropertyPairs.length; i += 2) {
            TableColumn<S, Object> c = new TableColumn<>(headerPropertyPairs[i]);
            c.setCellValueFactory(new PropertyValueFactory<>(headerPropertyPairs[i + 1]));
            table.getColumns().add(c);
        }
    }

    private Label placeholder(String t) {
        Label l = new Label(t);
        l.setStyle("-fx-text-fill: #344a60; -fx-font-family: 'Courier New'; -fx-font-size: 12px;");
        return l;
    }

    private Label smallLabel(String t) {
        Label l = new Label(t);
        l.setStyle("-fx-text-fill: #344a60; -fx-font-size: 10px; -fx-font-family: 'Courier New';");
        return l;
    }

    private HBox chip(String text, String color) { return new HBox(chipLabel(text, color)); }

    private Label chipLabel(String text, String color) {
        Label l = new Label(text.toUpperCase());
        l.setStyle("-fx-background-color: " + color + "15; -fx-text-fill: " + color + ";"
            + "-fx-background-radius: 3; -fx-padding: 4 10 4 10; -fx-font-size: 10px;"
            + "-fx-font-weight: bold; -fx-font-family: 'Courier New';");
        return l;
    }

    private javafx.scene.text.Text heading(String s) {
        javafx.scene.text.Text t = new javafx.scene.text.Text(s);
        t.setStyle("-fx-font-size: 20px; -fx-font-weight: bold; -fx-fill: #f0f4f8;");
        return t;
    }

    private javafx.scene.text.Text subheading(String s) {
        javafx.scene.text.Text t = new javafx.scene.text.Text(s);
        t.setStyle("-fx-font-size: 14px; -fx-font-weight: bold; -fx-fill: #f5a623;");
        return t;
    }

    private javafx.scene.text.Text body(String s) {
        javafx.scene.text.Text t = new javafx.scene.text.Text(s);
        t.setStyle("-fx-font-size: 13px; -fx-fill: #b8c7d6;");
        return t;
    }

    private void setProgress(double val, String label, String pct) {
        Platform.runLater(() -> {
            progressBar.setProgress(val);
            progressLabel.setText(label);
            progressPct.setText(pct);
        });
    }

    private String pctText(double pct) { return (int) (pct * 100) + "%"; }

    private void log(String line) {
        Platform.runLater(() -> console.appendText(line + "\n"));
    }

    private static double msSince(long nanoStart) {
        return (System.nanoTime() - nanoStart) / 1_000_000.0;
    }

    private static double median(List<Double> values) {
        if (values == null || values.isEmpty()) return 0;
        List<Double> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        int n = sorted.size();
        return (n % 2 == 1) ? sorted.get(n / 2)
                            : (sorted.get(n / 2 - 1) + sorted.get(n / 2)) / 2.0;
    }
}
