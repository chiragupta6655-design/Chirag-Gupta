package com.securestorage.ui.views;

import com.securestorage.auth.Permission;
import com.securestorage.logging.AuditLogger;
import com.securestorage.ui.AppState;
import com.securestorage.ui.Theme;
import com.securestorage.ui.components.UiHelper;
import javafx.collections.*;
import javafx.geometry.*;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.*;

import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Audit Log view — shows structured event log.
 * Accessible to ADMIN and AUDITOR roles only.
 */
public class AuditLogView extends VBox {

    private final ObservableList<LogRow> tableData = FXCollections.observableArrayList();
    private ComboBox<String> filterBox;

    public AuditLogView() {
        super(24);
        setPadding(new Insets(32));
        setStyle("-fx-background-color: #0a0e1a;");
        build();
    }

    private void build() {
        // RBAC check
        try {
            AppState.get().getAuthManager().requirePermission(
                AppState.get().getCurrentUser(), Permission.VIEW_LOGS);
        } catch (SecurityException e) {
            getChildren().add(UiHelper.cardAccent(
                UiHelper.labelDanger("✗  Access Denied"),
                UiHelper.labelSecondary("Only ADMIN and AUDITOR roles can view audit logs.")));
            return;
        }

        VBox header = UiHelper.sectionHeader("Audit Logs",
            "Immutable event trail for all system operations");

        // Stats row
        int total   = AppState.get().getAuditLogger().getAllLogs().size();
        int secEvts = AppState.get().getAuditLogger().getSecurityEvents().size();
        HBox stats  = new HBox(12,
            UiHelper.statCard(String.valueOf(total),   "Total Events",    Theme.ACCENT_CYAN),
            UiHelper.statCard(String.valueOf(secEvts), "Security Alerts", Theme.ACCENT_RED),
            UiHelper.statCard(String.valueOf(
                AppState.get().getAuditLogger().getLogsByAction("LOGIN").size()),
                "Logins", Theme.ACCENT_GREEN)
        );

        // Filter + refresh
        filterBox = new ComboBox<>();
        filterBox.getItems().addAll("ALL", "LOGIN", "LOGIN_FAIL", "UPLOAD", "DOWNLOAD",
            "DELETE", "ACCESS_DENIED", "ACCESS_GRANTED", "REGISTER");
        filterBox.setValue("ALL");
        filterBox.setStyle("-fx-background-color:#1a2235;-fx-border-color:#1e2d45;-fx-border-radius:6;-fx-text-fill:#e8edf5;");
        filterBox.setOnAction(e -> refreshTable());

        Button refreshBtn = UiHelper.btnGhost("↻  Refresh");
        refreshBtn.setOnAction(e -> refreshTable());

        Label filterLbl = new Label("Filter:");
        filterLbl.setStyle("-fx-text-fill:#8899aa;-fx-font-size:12px;");
        HBox toolbar = UiHelper.hbox(10, filterLbl, filterBox, refreshBtn, UiHelper.spacer());

        // Table
        TableView<LogRow> table = new TableView<>(tableData);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        VBox.setVgrow(table, Priority.ALWAYS);
        table.getColumns().addAll(
            lCol("Timestamp",  "timestamp", 160),
            lCol("Action",     "action",    160),
            lCol("User",       "username",   110),
            lCol("Details",    "message",   350)
        );

        refreshTable();
        getChildren().addAll(header, UiHelper.divider(), stats, toolbar, table);
    }

    private void refreshTable() {
        tableData.clear();
        String filter = filterBox.getValue();
        List<AuditLogger.LogEntry> logs = "ALL".equals(filter)
            ? AppState.get().getAuditLogger().getAllLogs()
            : AppState.get().getAuditLogger().getLogsByAction(filter);

        for (int i = logs.size() - 1; i >= 0; i--)
            tableData.add(new LogRow(logs.get(i)));
    }

    @SuppressWarnings("unchecked")
    private <T> TableColumn<LogRow, T> lCol(String n, String p, double w) {
        TableColumn<LogRow, T> c = new TableColumn<>(n);
        c.setCellValueFactory(new PropertyValueFactory<>(p)); c.setPrefWidth(w); return c;
    }

    public static class LogRow {
        private final String timestamp, action, username, message;
        LogRow(AuditLogger.LogEntry e) {
            this.timestamp = e.timestamp().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            this.action    = e.action();
            this.username  = e.username();
            this.message   = e.message();
        }
        public String getTimestamp() { return timestamp; }
        public String getAction()    { return action; }
        public String getUsername()  { return username; }
        public String getMessage()   { return message; }
    }
}
