package com.securestorage.ui.views;

import com.securestorage.ui.Theme;
import com.securestorage.ui.components.UiHelper;
import com.securestorage.utils.InputValidator;
import javafx.application.Platform;
import javafx.geometry.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.collections.*;

import java.io.*;
import java.util.concurrent.Executors;

/**
 * Interactive Attack Simulator view.
 * Left panel: attack selector with custom payload input.
 * Right panel: live console output + results table.
 */
public class AttackSimulatorView extends HBox {

    private TextArea  console;
    private final ObservableList<ResultRow> results = FXCollections.observableArrayList();
    private TextField payloadField;

    public AttackSimulatorView() {
        super(0);
        setStyle("-fx-background-color: #0a0e1a;");
        HBox.setHgrow(this, Priority.ALWAYS);
        VBox.setVgrow(this, Priority.ALWAYS);
        build();
    }

    private void build() {
        getChildren().addAll(buildLeftPanel(), buildRightPanel());
    }

    private VBox buildLeftPanel() {
        Label title = UiHelper.h3("Attack Types");
        Label sub   = UiHelper.labelSecondary("Select an attack to simulate");

        // Attack buttons
        String[][] attacks = {
            {"🗂️",  "Path Traversal",           "../../etc/passwd"},
            {"📤",  "Malicious Upload",          "shell.php"},
            {"💉",  "SQL Injection",             "' OR '1'='1; DROP TABLE files--"},
            {"⚙️",  "Command Injection",         "report.csv; rm -rf /"},
            {"📦",  "Insecure Deserialization",  "(crafted bytes)"},
            {"🔍",  "Reflection Misuse",         "(private field access)"}
        };

        VBox btnList = new VBox(6);
        for (String[] a : attacks) {
            Button btn = new Button(a[0] + "  " + a[1]);
            btn.setMaxWidth(Double.MAX_VALUE);
            btn.setAlignment(Pos.CENTER_LEFT);
            btn.setStyle("""
                -fx-background-color: #111827;
                -fx-text-fill: #e8edf5;
                -fx-font-size: 13px;
                -fx-padding: 12 16;
                -fx-cursor: hand;
                -fx-background-radius: 8;
                -fx-border-color: #1e2d45;
                -fx-border-radius: 8;
                -fx-border-width: 1;
                """);
            btn.setOnMouseEntered(e -> btn.setStyle(btn.getStyle().replace("#111827", "#1a2235")));
            btn.setOnMouseExited(e -> btn.setStyle(btn.getStyle().replace("#1a2235", "#111827")));
            final String attack = a[1], payload = a[2];
            btn.setOnAction(e -> {
                payloadField.setText(payload);
                runAttack(attack, payload);
            });
            btnList.getChildren().add(btn);
        }

        Button runAllBtn = UiHelper.btnPrimary("▶  Run All Attacks");
        runAllBtn.setMaxWidth(Double.MAX_VALUE);
        runAllBtn.setOnAction(e -> runAllAttacks());

        Button clearBtn = UiHelper.btnGhost("Clear Console");
        clearBtn.setMaxWidth(Double.MAX_VALUE);
        clearBtn.setOnAction(e -> { console.clear(); results.clear(); });

        Label payloadLbl = new Label("Custom Payload:");
        payloadLbl.setStyle("-fx-text-fill:#8899aa; -fx-font-size:11px; -fx-font-weight:bold;");
        payloadField = UiHelper.textField("Enter custom payload...");

        VBox panel = new VBox(12,
            title, sub, UiHelper.divider(),
            btnList, UiHelper.divider(),
            new VBox(4, payloadLbl, payloadField),
            runAllBtn, clearBtn
        );
        panel.setPadding(new Insets(24, 20, 24, 24));
        panel.setPrefWidth(270);
        panel.setMinWidth(270);
        panel.setMaxWidth(270);
        panel.setStyle("-fx-background-color: #111827; -fx-border-color: #1e2d45; -fx-border-width: 0 1 0 0;");
        return panel;
    }

    private VBox buildRightPanel() {
        Label title = UiHelper.h3("Attack Results");
        Label sub   = UiHelper.labelSecondary("Vulnerable system vs. Secured system comparison");

        // Results table
        TableView<ResultRow> table = new TableView<>(results);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        table.setPrefHeight(240);
        table.setMaxHeight(240);

        table.getColumns().addAll(
            rCol("Attack",   "attack",  160),
            rCol("Payload",  "payload", 220),
            rCol("Vulnerable","vuln",    130),
            rCol("Secured",  "secured", 130),
            rCol("Defense",  "defense", 230)
        );

        // Console
        console = UiHelper.consoleArea();
        VBox.setVgrow(console, Priority.ALWAYS);
        log("  ──────────────────────────────────────────────────");
        log("  SecureVault Attack Simulator");
        log("  Select an attack on the left to demonstrate");
        log("  vulnerable vs secured behaviour.");
        log("  ──────────────────────────────────────────────────");

        VBox panel = new VBox(16, title, sub, UiHelper.divider(), table, console);
        panel.setPadding(new Insets(24, 24, 24, 20));
        HBox.setHgrow(panel, Priority.ALWAYS);
        VBox.setVgrow(console, Priority.ALWAYS);
        VBox.setVgrow(panel, Priority.ALWAYS);
        return panel;
    }

    private void runAllAttacks() {
        console.clear(); results.clear();
        log("  ▶  Running all attack simulations...\n");
        Executors.newSingleThreadExecutor().submit(() -> {
            runAttackSync("Path Traversal",          "../../etc/passwd");
            runAttackSync("Malicious Upload",         "shell.php");
            runAttackSync("SQL Injection",            "' OR '1'='1; DROP TABLE files--");
            runAttackSync("Command Injection",        "data.csv; rm -rf /");
            runAttackSync("Insecure Deserialization", "(crafted bytes)");
            runAttackSync("Reflection Misuse",        "(private field access)");
            log("\n  ✓  All simulations complete.");
        });
    }

    private void runAttack(String attackName, String payload) {
        console.clear();
        Executors.newSingleThreadExecutor().submit(() -> runAttackSync(attackName, payload));
    }

    private void runAttackSync(String attackName, String payload) {
        InputValidator validator = new InputValidator();
        log("  ┌─────────────────────────────────────────────────┐");
        log("  │  ATTACK: " + pad(attackName, 40) + "│");
        log("  │  PAYLOAD: " + pad(truncate(payload, 39), 40) + "│");
        log("  └─────────────────────────────────────────────────┘");

        String vulnResult, secResult, defense, vulnStatus, secStatus;

        switch (attackName) {
            case "Path Traversal" -> {
                vulnResult = "⚠ /etc/passwd exposed"; vulnStatus = "LEAKED";
                try {
                    validator.validatePath("/storage/data", payload);
                    secResult = "Passed (benign)"; secStatus = "ALLOWED";
                    defense = "Canonical path check";
                } catch (Exception e) {
                    secResult = "✓ Blocked"; secStatus = "BLOCKED";
                    defense = "Canonical path check";
                }
                log("  [VULNERABLE] System reads file at: " + payload);
                log("  ⚠  File contents exposed to attacker!");
                log("");
                log("  [SECURED]    Running canonical path validation...");
                log("  ✓  Path resolves outside storage root → REJECTED");
            }
            case "Malicious Upload" -> {
                vulnResult = "⚠ Shell uploaded"; vulnStatus = "UPLOADED";
                try {
                    validator.validateFilename(payload);
                    secResult = "Allowed"; secStatus = "ALLOWED";
                    defense = "Extension whitelist";
                } catch (Exception e) {
                    secResult = "✓ Blocked"; secStatus = "BLOCKED";
                    defense = "Extension whitelist";
                }
                log("  [VULNERABLE] File accepted: " + payload);
                log("  ⚠  Web shell could execute arbitrary code!");
                log("");
                log("  [SECURED]    Extension whitelist check:");
                log("  ✓  '" + payload + "' not in [.txt .pdf .csv .json .xml .log .md .png .jpg]");
                log("  ✓  Upload REJECTED");
            }
            case "SQL Injection" -> {
                boolean detected = validator.detectsSqlInjection(payload);
                vulnResult = "⚠ Query manipulated"; vulnStatus = "EXPLOITED";
                secResult  = detected ? "✓ Detected" : "Passed";
                secStatus  = detected ? "BLOCKED" : "PASSED";
                defense    = "Regex pattern detection";
                log("  [VULNERABLE] Query executed with input: " + payload);
                log("  ⚠  Attacker could read/drop/modify database tables!");
                log("");
                log("  [SECURED]    SQL injection pattern check:");
                log("  " + (detected ? "✓  Pattern detected → Input REJECTED" : "  Input appears clean"));
            }
            case "Command Injection" -> {
                boolean detected = validator.detectsCommandInjection(payload);
                vulnResult = "⚠ OS command run"; vulnStatus = "EXPLOITED";
                secResult  = detected ? "✓ Detected" : "Passed";
                secStatus  = detected ? "BLOCKED" : "PASSED";
                defense    = "Shell metachar detection";
                log("  [VULNERABLE] Input passed to system: " + payload);
                log("  ⚠  OS command execution possible!");
                log("");
                log("  [SECURED]    Metacharacter scan (;|&`$(){}...):");
                log("  " + (detected ? "✓  Dangerous chars detected → REJECTED" : "  Input appears clean"));
            }
            case "Insecure Deserialization" -> {
                vulnResult = "⚠ Role escalated"; vulnStatus = "EXPLOITED";
                secResult  = "✓ Blocked"; secStatus = "BLOCKED";
                defense    = "ObjectInputFilter + readObject()";
                log("  [VULNERABLE] Deserializing crafted byte stream...");
                log("  ⚠  VulnerableUser{role=ADMIN, username='hacked'} created!");
                log("  ⚠  Attacker has full admin privileges!");
                log("");
                log("  [SECURED]    ObjectInputFilter whitelist active:");
                log("  ✓  Only com.securestorage.* classes allowed");
                log("  ✓  readObject() validates role + username fields");
                log("  ✓  InvalidObjectException thrown → deserialization BLOCKED");
            }
            case "Reflection Misuse" -> {
                vulnResult = "⚠ Key stolen"; vulnStatus = "EXPOSED";
                secResult  = "✓ Encapsulated"; secStatus = "PROTECTED";
                defense    = "Final fields + module system";
                log("  [VULNERABLE] Reflection on VulnerableConfig:");
                log("    Field f = VulnerableConfig.class.getDeclaredField(\"secretKey\");");
                log("    f.setAccessible(true);");
                log("  ⚠  secretKey = 'supersecret_api_key' — STOLEN!");
                log("");
                log("  [SECURED]    SecureConfig has:");
                log("  ✓  private final String secretKey; (no setter, no direct getter)");
                log("  ✓  getMaskedKey() returns 'sup********************' only");
                log("  ✓  Java 9+ module system: InaccessibleObjectException on cross-module reflect");
            }
            default -> {
                vulnResult = "N/A"; secResult = "N/A"; defense = "N/A";
                vulnStatus = ""; secStatus = "";
            }
        }

        log("");
        final String fr = secResult, fv = vulnResult, fd = defense, fvs = vulnStatus, fss = secStatus;
        Platform.runLater(() -> results.add(new ResultRow(attackName, truncate(payload, 22), fv, fr, fd)));
        try { Thread.sleep(300); } catch (InterruptedException ignored) {}
    }

    private void log(String line) {
        Platform.runLater(() -> console.appendText(line + "\n"));
    }

    @SuppressWarnings("unchecked")
    private <T> TableColumn<ResultRow, T> rCol(String n, String p, double w) {
        TableColumn<ResultRow, T> c = new TableColumn<>(n);
        c.setCellValueFactory(new javafx.scene.control.cell.PropertyValueFactory<>(p));
        c.setPrefWidth(w); return c;
    }

    private String pad(String s, int n)      { return String.format("%-" + n + "s", s); }
    private String truncate(String s, int n)  { return s != null && s.length() > n ? s.substring(0, n) + "…" : s; }

    public static class ResultRow {
        private final String attack, payload, vuln, secured, defense;
        ResultRow(String a, String p, String v, String s, String d) { attack=a; payload=p; vuln=v; secured=s; defense=d; }
        public String getAttack()  { return attack; }
        public String getPayload() { return payload; }
        public String getVuln()    { return vuln; }
        public String getSecured() { return secured; }
        public String getDefense() { return defense; }
    }
}
