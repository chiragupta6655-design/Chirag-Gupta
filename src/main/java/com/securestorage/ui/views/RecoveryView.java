package com.securestorage.ui.views;

import com.securestorage.ui.AppState;
import com.securestorage.ui.Theme;
import com.securestorage.ui.components.UiHelper;
import javafx.application.Platform;
import javafx.geometry.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;

import java.util.*;
import java.util.concurrent.Executors;

/**
 * Recovery & Fault Tolerance panel.
 * Shows WAL entries, checkpoint controls, and reliability metrics.
 */
public class RecoveryView extends VBox {

    private TextArea walArea, metricsArea;
    private Label statusLabel;

    public RecoveryView() {
        super(24);
        setPadding(new Insets(32));
        setStyle("-fx-background-color: #0a0e1a;");
        build();
    }

    private void build() {
        VBox header = UiHelper.sectionHeader("Recovery & Fault Tolerance",
            "Write-Ahead Log (WAL) + checkpoint-based crash recovery");

        // ── Metrics cards ─────────────────────────────────────────
        int  chkpts   = AppState.get().getCheckpointManager().getCheckpointsSaved();
        int  recovers = AppState.get().getCheckpointManager().getRecoveryAttempts();
        List<String> snapList = AppState.get().getCheckpointManager().listCheckpoints();

        HBox metricsRow = new HBox(16,
            UiHelper.statCard(String.valueOf(chkpts),       "Checkpoints Saved", Theme.ACCENT_CYAN),
            UiHelper.statCard(String.valueOf(recovers),     "Recovery Attempts", Theme.ACCENT_AMBER),
            UiHelper.statCard(String.valueOf(snapList.size()),"Snapshot Files",  Theme.ACCENT_GREEN)
        );

        // ── Controls ──────────────────────────────────────────────
        Button saveChkBtn  = UiHelper.btnPrimary("💾  Save Checkpoint");
        Button loadChkBtn  = UiHelper.btnGhost("⟳  Load Latest");
        Button scanWalBtn  = UiHelper.btnGhost("🔍  Scan WAL");
        statusLabel = new Label(" ");
        statusLabel.setStyle("-fx-font-size:12px;-fx-text-fill:#00ff9f;");

        saveChkBtn.setOnAction(e -> saveCheckpoint());
        loadChkBtn.setOnAction(e -> loadCheckpoint());
        scanWalBtn.setOnAction(e -> scanWAL());

        HBox controls = UiHelper.hbox(12, saveChkBtn, loadChkBtn, scanWalBtn,
            UiHelper.spacer(), statusLabel);

        // ── Two-column detail ─────────────────────────────────────
        walArea     = UiHelper.consoleArea();
        metricsArea = UiHelper.consoleArea();
        walArea.setPrefRowCount(12);
        metricsArea.setPrefRowCount(12);
        walArea.appendText("  [WAL] Click '🔍 Scan WAL' to view transaction log\n");
        metricsArea.appendText("  [METRICS] Click '💾 Save Checkpoint' to begin\n");

        HBox.setHgrow(walArea, Priority.ALWAYS);
        HBox.setHgrow(metricsArea, Priority.ALWAYS);

        VBox walBox = new VBox(8, UiHelper.h3("Transaction Log (WAL)"), walArea);
        VBox metBox = new VBox(8, UiHelper.h3("Checkpoint Metrics"), metricsArea);
        HBox.setHgrow(walBox, Priority.ALWAYS);
        HBox.setHgrow(metBox, Priority.ALWAYS);

        HBox detail = new HBox(16, walBox, metBox);
        VBox.setVgrow(detail, Priority.ALWAYS);

        // ── How it works ──────────────────────────────────────────
        VBox howBox = buildHowItWorks();

        getChildren().addAll(header, UiHelper.divider(), metricsRow, controls,
            UiHelper.divider(), detail, howBox);
    }

    private void saveCheckpoint() {
        Executors.newSingleThreadExecutor().submit(() -> {
            try {
                Map<String, Object> state = new HashMap<>();
                state.put("fileCount",   AppState.get().getFileStorage().getFileCount());
                state.put("userCount",   AppState.get().getAuthManager().getAllUsers().size());
                state.put("logEntries",  AppState.get().getAuditLogger().getAllLogs().size());
                state.put("timestamp",   System.currentTimeMillis());
                AppState.get().getCheckpointManager().saveCheckpoint(state);

                Platform.runLater(() -> {
                    setStatus("✓  Checkpoint saved successfully", Theme.ACCENT_GREEN);
                    metricsArea.appendText("  [CHECKPOINT] Saved state:\n");
                    state.forEach((k, v) ->
                        metricsArea.appendText("    " + k + " = " + v + "\n"));
                    metricsArea.appendText("  Saved checkpoints: " +
                        AppState.get().getCheckpointManager().listCheckpoints() + "\n\n");
                });
            } catch (Exception ex) {
                Platform.runLater(() -> setStatus("✗  " + ex.getMessage(), Theme.ACCENT_RED));
            }
        });
    }

    private void loadCheckpoint() {
        Executors.newSingleThreadExecutor().submit(() -> {
            try {
                Map<String, Object> restored =
                    AppState.get().getCheckpointManager().loadLatestCheckpoint();
                Platform.runLater(() -> {
                    if (restored.isEmpty()) {
                        setStatus("⚠  No checkpoints found", Theme.ACCENT_AMBER);
                    } else {
                        setStatus("✓  Latest checkpoint loaded", Theme.ACCENT_GREEN);
                        metricsArea.appendText("  [RECOVERY] Restored state:\n");
                        restored.forEach((k, v) ->
                            metricsArea.appendText("    " + k + " = " + v + "\n"));
                        metricsArea.appendText("\n");
                    }
                });
            } catch (Exception ex) {
                Platform.runLater(() -> setStatus("✗  " + ex.getMessage(), Theme.ACCENT_RED));
            }
        });
    }

    private void scanWAL() {
        Executors.newSingleThreadExecutor().submit(() -> {
            try {
                List<String> incomplete =
                    AppState.get().getTransactionLog().findIncompleteTransactions();
                Platform.runLater(() -> {
                    walArea.clear();
                    walArea.appendText("  [WAL SCAN] Transaction log analysis:\n\n");
                    if (incomplete.isEmpty()) {
                        walArea.appendText("  ✓  No incomplete transactions found.\n");
                        walArea.appendText("  ✓  All operations committed or rolled back.\n");
                        walArea.appendText("  ✓  System state is CONSISTENT.\n");
                    } else {
                        walArea.appendText("  ⚠  Incomplete transactions detected!\n");
                        for (String id : incomplete)
                            walArea.appendText("    → " + id + " (would rollback)\n");
                    }
                    walArea.appendText("\n  WAL file: " + AppState.BASE_DIR + "/recovery/transaction.wal\n");
                    setStatus("✓  WAL scan complete", Theme.ACCENT_GREEN);
                });
            } catch (Exception ex) {
                Platform.runLater(() -> setStatus("✗  " + ex.getMessage(), Theme.ACCENT_RED));
            }
        });
    }

    private VBox buildHowItWorks() {
        Label t = UiHelper.h3("How WAL Recovery Works");
        Label d = UiHelper.labelSecondary(
            "1. Every operation logs BEGIN before executing.\n" +
            "2. On success, COMMIT is written — operation is durable.\n" +
            "3. On crash between BEGIN and COMMIT, the operation is marked incomplete.\n" +
            "4. At next startup, scan WAL → roll back incomplete operations.\n" +
            "5. Load latest checkpoint → replay WAL from that point.");
        d.setWrapText(true);
        d.setStyle("-fx-text-fill:#8899aa; -fx-font-size:12px; -fx-line-spacing:4;");

        VBox box = new VBox(8, t, d);
        box.getStyleClass().add("card");
        return box;
    }

    private void setStatus(String m, String c) {
        statusLabel.setText(m);
        statusLabel.setStyle("-fx-font-size:12px;-fx-text-fill:" + c + ";");
    }
}
