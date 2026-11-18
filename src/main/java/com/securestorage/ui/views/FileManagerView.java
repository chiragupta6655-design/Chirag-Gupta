package com.securestorage.ui.views;

import com.securestorage.auth.Permission;
import com.securestorage.auth.Role;
import com.securestorage.storage.FileMetadata;
import com.securestorage.ui.AppState;
import com.securestorage.ui.Theme;
import com.securestorage.ui.components.UiHelper;
import javafx.collections.*;
import javafx.geometry.*;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.*;
import javafx.stage.*;
import javafx.scene.control.TableColumn;

import java.io.*;
import java.nio.file.*;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * File Manager — upload files from disk, download back, delete (admin), table view.
 */
public class FileManagerView extends VBox {

    private final ObservableList<FileRow> tableData = FXCollections.observableArrayList();
    private TableView<FileRow> table;
    private Label statusLabel;

    public FileManagerView() {
        super(24);
        setPadding(new Insets(32));
        setStyle("-fx-background-color: #0a0e1a;");
        build();
    }

    private void build() {
        // ── Header ───────────────────────────────────────────────
        VBox header = UiHelper.sectionHeader("File Manager",
            "Upload, download and manage encrypted files");

        // ── Toolbar ──────────────────────────────────────────────
        Button uploadBtn   = UiHelper.btnPrimary("⬆  Upload File");
        Button downloadBtn = UiHelper.btnGhost("⬇  Download");
        Button deleteBtn   = UiHelper.btnDanger("✕  Delete");
        Button refreshBtn  = UiHelper.btnGhost("↻  Refresh");

        statusLabel = new Label(" ");
        statusLabel.setStyle("-fx-font-size: 12px; -fx-text-fill: #00ff9f;");

        // Role-based toolbar visibility
        boolean isAdmin = AppState.get().getCurrentUser().getRole() == Role.ADMIN;
        deleteBtn.setDisable(!isAdmin);
        if (!isAdmin) deleteBtn.setStyle(deleteBtn.getStyle() + "-fx-opacity:0.4;");

        uploadBtn.setOnAction(e -> handleUpload());
        downloadBtn.setOnAction(e -> handleDownload());
        deleteBtn.setOnAction(e -> handleDelete());
        refreshBtn.setOnAction(e -> refreshTable());

        HBox toolbar = UiHelper.hbox(10, uploadBtn, downloadBtn, deleteBtn, refreshBtn,
            UiHelper.spacer(), statusLabel);

        // ── Table ────────────────────────────────────────────────
        table = buildTable();
        VBox.setVgrow(table, Priority.ALWAYS);

        // ── Info bar ─────────────────────────────────────────────
        Label infoLabel = UiHelper.labelSecondary(
            "All files are encrypted with AES-256-GCM + RSA-2048-OAEP. " +
            "Integrity verified on every download.");
        infoLabel.setStyle("-fx-font-size: 11px; -fx-text-fill: #4a5568;");
        HBox infoBar = UiHelper.hbox(8,
            UiHelper.labelCode("🔒 AES-256-GCM"),
            UiHelper.labelCode("🔑 RSA-2048"),
            UiHelper.labelCode("✓ SHA-256 Integrity"),
            UiHelper.spacer(), infoLabel);
        infoBar.setPadding(new Insets(8, 12, 8, 12));
        infoBar.setStyle("-fx-background-color: #111827; -fx-background-radius: 8; -fx-border-color: #1e2d45; -fx-border-radius: 8; -fx-border-width: 1;");

        getChildren().addAll(header, UiHelper.divider(), toolbar, table, infoBar);
        refreshTable();
    }

    private TableView<FileRow> buildTable() {
        TableView<FileRow> tv = new TableView<>(tableData);
        tv.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        tv.setPlaceholder(new Label("No files yet — click ⬆ Upload File to get started"));
        tv.getPlaceholder().setStyle("-fx-text-fill: #4a5568;");

        tv.getColumns().addAll(
            col("File Name",  "name",       220),
            col("Owner",      "owner",       90),
            col("Size",       "size",        80),
            col("Uploaded",   "uploaded",   155),
            col("Integrity",  "integrity",   90),
            col("File ID",    "fileId",     180)
        );
        return tv;
    }

    @SuppressWarnings("unchecked")
    private <T> TableColumn<FileRow, T> col(String name, String prop, double width) {
        TableColumn<FileRow, T> c = new TableColumn<>(name);
        c.setCellValueFactory(new PropertyValueFactory<>(prop));
        c.setPrefWidth(width);
        c.setStyle("-fx-alignment: CENTER-LEFT;");
        return c;
    }

    private void refreshTable() {
        try {
            String token = AppState.get().getCurrentToken();
            List<FileMetadata> files = AppState.get().getFileStorage().listFiles(token);
            tableData.clear();
            for (FileMetadata m : files) {
                tableData.add(new FileRow(m));
            }
            setStatus("✓  " + files.size() + " file(s) loaded", Theme.ACCENT_GREEN);
        } catch (Exception e) {
            setStatus("✗  " + e.getMessage(), Theme.ACCENT_RED);
        }
    }

    private void handleUpload() {
        FileChooser fc = new FileChooser();
        fc.setTitle("Select File to Encrypt and Upload");
        fc.getExtensionFilters().addAll(
            new FileChooser.ExtensionFilter("Allowed Files",
                "*.txt","*.pdf","*.csv","*.json","*.xml","*.log","*.md","*.png","*.jpg","*.jpeg"),
            new FileChooser.ExtensionFilter("All Files", "*.*")
        );
        File file = fc.showOpenDialog(getScene().getWindow());
        if (file == null) return;

        try {
            byte[] content = Files.readAllBytes(file.toPath());
            AppState.get().getFileStorage()
                .uploadFile(AppState.get().getCurrentToken(), file.getName(), content);
            refreshTable();
            setStatus("✓  '" + file.getName() + "' encrypted and stored successfully", Theme.ACCENT_GREEN);
        } catch (Exception ex) {
            setStatus("✗  " + ex.getMessage(), Theme.ACCENT_RED);
        }
    }

    private void handleDownload() {
        FileRow selected = table.getSelectionModel().getSelectedItem();
        if (selected == null) { setStatus("⚠  Select a file first", Theme.ACCENT_AMBER); return; }

        FileChooser fc = new FileChooser();
        fc.setTitle("Save Decrypted File");
        fc.setInitialFileName(selected.getName());
        File dest = fc.showSaveDialog(getScene().getWindow());
        if (dest == null) return;

        try {
            byte[] decrypted = AppState.get().getFileStorage()
                .downloadFile(AppState.get().getCurrentToken(), selected.getRawFileId());
            Files.write(dest.toPath(), decrypted);
            setStatus("✓  Decrypted and saved to: " + dest.getName(), Theme.ACCENT_GREEN);
        } catch (Exception ex) {
            setStatus("✗  " + ex.getMessage(), Theme.ACCENT_RED);
        }
    }

    private void handleDelete() {
        FileRow selected = table.getSelectionModel().getSelectedItem();
        if (selected == null) { setStatus("⚠  Select a file first", Theme.ACCENT_AMBER); return; }

        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION,
            "Permanently delete '" + selected.getName() + "'?",
            ButtonType.YES, ButtonType.CANCEL);
        confirm.setHeaderText("Confirm Delete");
        confirm.getDialogPane().setStyle("-fx-background-color: #111827; -fx-font-size: 13px;");
        confirm.showAndWait().ifPresent(btn -> {
            if (btn == ButtonType.YES) {
                try {
                    AppState.get().getFileStorage()
                        .deleteFile(AppState.get().getCurrentToken(), selected.getRawFileId());
                    refreshTable();
                    setStatus("✓  File deleted", Theme.ACCENT_GREEN);
                } catch (Exception ex) {
                    setStatus("✗  " + ex.getMessage(), Theme.ACCENT_RED);
                }
            }
        });
    }

    private void setStatus(String msg, String color) {
        statusLabel.setText(msg);
        statusLabel.setStyle("-fx-font-size: 12px; -fx-text-fill: " + color + ";");
    }

    // ── Table row model ──────────────────────────────────────────

    public static class FileRow {
        private final String name, owner, size, uploaded, integrity, fileId;
        private final String rawFileId;

        FileRow(FileMetadata m) {
            this.name       = m.getOriginalName();
            this.owner      = m.getOwnerUsername();
            this.size       = formatSize(m.getOriginalSizeBytes());
            this.uploaded   = m.getUploadedAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            this.integrity  = "✓ SHA-256";
            this.fileId     = m.getFileId().substring(0, 13) + "...";
            this.rawFileId  = m.getFileId();
        }

        public String getName()      { return name; }
        public String getOwner()     { return owner; }
        public String getSize()      { return size; }
        public String getUploaded()  { return uploaded; }
        public String getIntegrity() { return integrity; }
        public String getFileId()    { return fileId; }
        public String getRawFileId() { return rawFileId; }

        private static String formatSize(long bytes) {
            if (bytes >= 1_048_576) return String.format("%.1f MB", bytes / 1_048_576.0);
            if (bytes >= 1_024)     return String.format("%.1f KB", bytes / 1_024.0);
            return bytes + " B";
        }
    }
}
