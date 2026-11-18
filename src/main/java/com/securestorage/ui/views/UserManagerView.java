package com.securestorage.ui.views;

import com.securestorage.auth.*;
import com.securestorage.ui.AppState;
import com.securestorage.ui.Theme;
import com.securestorage.ui.components.UiHelper;
import javafx.collections.*;
import javafx.geometry.*;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.*;

import java.time.format.DateTimeFormatter;
import java.util.Collection;

/**
 * User Manager — register new users, view all accounts, deactivate.
 * Admin-only page (deactivate button disabled for non-admins).
 */
public class UserManagerView extends VBox {

    private final ObservableList<UserRow> tableData = FXCollections.observableArrayList();
    private Label statusLabel;

    public UserManagerView() {
        super(24);
        setPadding(new Insets(32));
        setStyle("-fx-background-color: #0a0e1a;");
        build();
    }

    private void build() {
        VBox header = UiHelper.sectionHeader("User Manager", "Register and manage system accounts");

        // ── Register form ─────────────────────────────────────────
        TextField userField = UiHelper.textField("Username");
        PasswordField passField = UiHelper.passwordField("Password (min 8, upper+digit+symbol)");
        ComboBox<String> roleBox = new ComboBox<>();
        roleBox.getItems().addAll("USER", "AUDITOR", "ADMIN");
        roleBox.setValue("USER");
        roleBox.setStyle("-fx-background-color: #1a2235; -fx-border-color: #1e2d45; -fx-border-radius: 6; -fx-text-fill: #e8edf5;");
        userField.setMaxWidth(220); passField.setMaxWidth(280); roleBox.setMaxWidth(130);

        Button addBtn = UiHelper.btnSuccess("+ Add User");
        addBtn.setOnAction(e -> handleAdd(userField.getText(), passField.getText(), roleBox.getValue()));

        statusLabel = new Label(" ");
        statusLabel.setStyle("-fx-font-size: 12px; -fx-text-fill: #00ff9f;");

        HBox form = UiHelper.hbox(12,
            labeledField("Username", userField),
            labeledField("Password", passField),
            labeledField("Role", roleBox),
            addBtn, UiHelper.spacer(), statusLabel);
        form.setAlignment(Pos.BOTTOM_LEFT);
        form.setPadding(new Insets(16));
        form.setStyle("-fx-background-color: #111827; -fx-background-radius: 10; -fx-border-color: #1e2d45; -fx-border-radius: 10; -fx-border-width: 1;");

        // ── Table ─────────────────────────────────────────────────
        TableView<UserRow> table = new TableView<>(tableData);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        VBox.setVgrow(table, Priority.ALWAYS);
        table.getColumns().addAll(
            uCol("Username",   "username",  160),
            uCol("Role",       "role",      100),
            uCol("Status",     "active",     90),
            uCol("Created",    "created",   170),
            uCol("User ID",    "userId",    250)
        );

        boolean isAdmin = AppState.get().getCurrentUser().getRole() == Role.ADMIN;
        if (isAdmin) {
            TableColumn<UserRow, Void> actCol = new TableColumn<>("Action");
            actCol.setPrefWidth(110);
            actCol.setCellFactory(tc -> new TableCell<>() {
                final Button b = UiHelper.btnDanger("Deactivate");
                { b.setOnAction(e -> { UserRow r = getTableView().getItems().get(getIndex()); deactivate(r.getUsername()); }); }
                @Override protected void updateItem(Void v, boolean empty) {
                    super.updateItem(v, empty);
                    setGraphic(empty ? null : b);
                }
            });
            table.getColumns().add(actCol);
        }

        refreshTable();
        getChildren().addAll(header, UiHelper.divider(), form, table);
    }

    private void handleAdd(String u, String p, String role) {
        try {
            AppState.get().getAuthManager().registerUser(u, p, Role.valueOf(role));
            refreshTable();
            setStatus("✓  User '" + u + "' created as " + role, Theme.ACCENT_GREEN);
        } catch (Exception ex) { setStatus("✗  " + ex.getMessage(), Theme.ACCENT_RED); }
    }

    private void deactivate(String username) {
        AppState.get().getAuthManager().deactivateUser(username);
        refreshTable();
        setStatus("✓  Deactivated: " + username, Theme.ACCENT_AMBER);
    }

    private void refreshTable() {
        tableData.clear();
        for (User u : AppState.get().getAuthManager().getAllUsers())
            tableData.add(new UserRow(u));
    }

    private void setStatus(String m, String c) { statusLabel.setText(m); statusLabel.setStyle("-fx-font-size:12px;-fx-text-fill:" + c + ";"); }

    private VBox labeledField(String lbl, javafx.scene.Node f) {
        Label l = new Label(lbl); l.setStyle("-fx-font-size:11px;-fx-text-fill:#8899aa;-fx-font-weight:bold;");
        return new VBox(4, l, f);
    }

    @SuppressWarnings("unchecked")
    private <T> TableColumn<UserRow, T> uCol(String n, String p, double w) {
        TableColumn<UserRow, T> c = new TableColumn<>(n);
        c.setCellValueFactory(new PropertyValueFactory<>(p)); c.setPrefWidth(w); return c;
    }

    public static class UserRow {
        private final String username, role, active, created, userId;
        UserRow(User u) {
            this.username = u.getUsername();
            this.role     = u.getRole().name();
            this.active   = u.isActive() ? "● Active" : "○ Inactive";
            this.created  = u.getCreatedAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            this.userId   = u.getUserId();
        }
        public String getUsername() { return username; }
        public String getRole()     { return role; }
        public String getActive()   { return active; }
        public String getCreated()  { return created; }
        public String getUserId()   { return userId; }
    }
}
