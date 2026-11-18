package com.securestorage.ui.views;

import com.securestorage.auth.Role;
import com.securestorage.auth.User;
import com.securestorage.config.SavedLogin;
import com.securestorage.ui.AppState;
import com.securestorage.ui.Theme;
import com.securestorage.ui.components.UiHelper;
import javafx.animation.*;
import javafx.application.Platform;
import javafx.geometry.*;
import javafx.scene.control.*;
import javafx.scene.effect.*;
import javafx.scene.layout.*;
import javafx.scene.paint.*;
import javafx.scene.shape.*;
import javafx.util.Duration;

import java.util.function.Consumer;

public class LoginView extends StackPane {

    private final Consumer<User> onLoginSuccess;
    private final SavedLogin savedLogin = new SavedLogin(AppState.BASE_DIR);

    private Label         statusLabel;
    private TextField     loginUserField;
    private PasswordField loginPassField;
    private CheckBox      rememberBox;
    private CheckBox      savePasswordBox;
    private Button        signInBtn;
    private ProgressIndicator busySpinner;

    public LoginView(Consumer<User> onLoginSuccess) {
        this.onLoginSuccess = onLoginSuccess;
        build();
    }

    private void build() {
        getStylesheets().add("data:text/css," + Theme.STYLESHEET.replace("\n", " "));
        setStyle("-fx-background-color: #080c14;");
        setPrefSize(1100, 720);
        getChildren().addAll(buildBackground(), new HBox(buildLeftPanel(), buildRightPanel()));
    }

    private StackPane buildBackground() {
        StackPane pane = new StackPane();
        pane.setStyle("-fx-background-color: #080c14;");
        for (int i = 0; i < 3; i++) {
            Circle c = new Circle(120 + i * 60);
            c.setFill(Color.TRANSPARENT);
            c.setStroke(Color.web("#f5a623", 0.04 - i * 0.01));
            c.setStrokeWidth(1);
            c.setTranslateX(-280 + i * 10);
            c.setTranslateY(100 - i * 20);
            pane.getChildren().add(c);
        }
        for (int row = 0; row < 8; row++) {
            for (int col = 0; col < 12; col++) {
                Circle dot = new Circle(1.2);
                dot.setFill(Color.web("#162338", 0.8));
                dot.setTranslateX(280 + col * 22);
                dot.setTranslateY(180 + row * 22);
                pane.getChildren().add(dot);
            }
        }
        return pane;
    }

    private VBox buildLeftPanel() {
        Label lockIcon = new Label("⬡");
        lockIcon.setStyle("-fx-font-size: 56px; -fx-text-fill: #f5a623;");
        DropShadow glow = new DropShadow();
        glow.setColor(Color.web("#f5a623", 0.6)); glow.setRadius(30); glow.setSpread(0.1);
        lockIcon.setEffect(glow);

        Label lock2 = new Label("🔐");
        lock2.setStyle("-fx-font-size: 26px;");
        StackPane iconStack = new StackPane(lockIcon, lock2);
        iconStack.setMaxSize(Region.USE_PREF_SIZE, Region.USE_PREF_SIZE);

        Label title = new Label("SECUREVAULT");
        title.setStyle(
            "-fx-font-size: 26px; -fx-font-weight: bold; -fx-text-fill: #f0f4f8;" +
            "-fx-font-family: 'Palatino Linotype', 'Georgia', serif; -fx-letter-spacing: 4;");

        Label subtitle = new Label("Advanced Cryptographic Storage");
        subtitle.setStyle("-fx-font-size: 12px; -fx-text-fill: #344a60; -fx-font-family: 'Courier New', monospace;");

        Region titleSep = new Region();
        titleSep.setPrefHeight(1); titleSep.setMaxWidth(60);
        titleSep.setStyle("-fx-background-color: #f5a623;");

        VBox features = new VBox(10,
            featureRow("AES-256-GCM + RSA-2048-OAEP",        "#f5a623"),
            featureRow("ML-KEM / ML-DSA / SLH-DSA benchmarks", "#8b5cf6"),
            featureRow("Private keys sealed at rest",          "#22c55e"),
            featureRow("Role-Based Access Control",            "#0ea5e9"),
            featureRow("PBKDF2 + BCrypt Password Hashing",     "#f5a623")
        );

        Label ver = new Label("VERSION 3.0.0  ·  JAVA 17+  ·  JAVAFX 17");
        ver.setStyle("-fx-font-size: 9px; -fx-text-fill: #162338; -fx-font-family: 'Courier New', monospace;");

        Region gap = new Region();
        gap.setPrefHeight(10);

        VBox panel = new VBox(22, iconStack, new VBox(6, title, titleSep, subtitle),
            gap, features, UiHelper.spacer(), ver);
        panel.setAlignment(Pos.CENTER_LEFT);
        panel.setPadding(new Insets(60, 50, 40, 60));
        panel.setMinWidth(400); panel.setMaxWidth(400);
        panel.setStyle("-fx-background-color: #080c14; -fx-border-color: #162338; -fx-border-width: 0 1 0 0;");
        return panel;
    }

    private HBox featureRow(String text, String color) {
        Region dot = new Region();
        dot.setPrefSize(5, 5); dot.setMaxSize(5, 5);
        dot.setStyle("-fx-background-color: " + color + "; -fx-background-radius: 50;");
        DropShadow ds = new DropShadow();
        ds.setColor(Color.web(color, 0.8)); ds.setRadius(6); ds.setSpread(0.3);
        dot.setEffect(ds);

        Label lbl = new Label(text);
        lbl.setStyle("-fx-text-fill: #7a8fa6; -fx-font-size: 12px;");

        HBox row = new HBox(12, dot, lbl);
        row.setAlignment(Pos.CENTER_LEFT);
        return row;
    }

    private VBox buildRightPanel() {
        ToggleButton loginTab = new ToggleButton("SIGN IN");
        ToggleButton regTab   = new ToggleButton("REGISTER");
        ToggleGroup  tg       = new ToggleGroup();
        loginTab.setToggleGroup(tg); regTab.setToggleGroup(tg);
        loginTab.setSelected(true);

        HBox tabs = new HBox(0, loginTab, regTab);
        tabs.setStyle("-fx-background-color: #0c1221; -fx-background-radius: 4;"
            + "-fx-border-color: #162338; -fx-border-radius: 4; -fx-border-width: 1;");
        tabs.setMaxWidth(320);

        StackPane formArea = new StackPane();
        VBox loginForm = buildLoginForm();
        VBox regForm   = buildRegisterForm();
        formArea.getChildren().addAll(loginForm, regForm);
        regForm.setVisible(false);

        loginTab.setOnAction(e -> { loginForm.setVisible(true); regForm.setVisible(false); status(" ", "#7a8fa6"); });
        regTab.setOnAction(e  -> { loginForm.setVisible(false); regForm.setVisible(true);  status(" ", "#7a8fa6"); });

        statusLabel = new Label(" ");
        statusLabel.setStyle("-fx-font-size: 12px; -fx-font-family: 'Courier New', monospace;");
        statusLabel.setMinHeight(18);
        statusLabel.setMaxWidth(320);
        statusLabel.setWrapText(true);

        Label heading = new Label("AUTHENTICATION");
        heading.setStyle("-fx-font-size: 22px; -fx-font-weight: bold; -fx-text-fill: #f0f4f8;"
            + "-fx-font-family: 'Palatino Linotype', 'Georgia', serif;");

        Label subHint = new Label(savedLogin.isEnabled()
            ? "Welcome back, " + savedLogin.getUsername()
            : "Default: admin / Admin@Secure123!");
        subHint.setStyle("-fx-font-size: 11px; -fx-text-fill: #344a60; -fx-font-family: 'Courier New', monospace;");

        VBox container = new VBox(24, new VBox(6, heading, subHint), tabs, formArea, statusLabel);
        container.setAlignment(Pos.CENTER);
        container.setMaxWidth(360);

        VBox right = new VBox(container);
        right.setAlignment(Pos.CENTER);
        right.setStyle("-fx-background-color: #080c14;");
        right.setPadding(new Insets(40));
        HBox.setHgrow(right, Priority.ALWAYS);

        right.setTranslateX(40); right.setOpacity(0);
        new Timeline(
            new KeyFrame(Duration.millis(0),
                new KeyValue(right.translateXProperty(), 40),
                new KeyValue(right.opacityProperty(), 0)),
            new KeyFrame(Duration.millis(600),
                new KeyValue(right.translateXProperty(), 0, Interpolator.EASE_OUT),
                new KeyValue(right.opacityProperty(), 1, Interpolator.EASE_OUT))
        ).play();

        return right;
    }

    // ── Sign-in form ─────────────────────────────────────────────────

    private VBox buildLoginForm() {
        loginUserField = UiHelper.textField("Username");
        loginUserField.setMaxWidth(320);
        loginPassField = UiHelper.passwordField("Password");
        loginPassField.setMaxWidth(320);

        // Restore whatever was remembered last time.
        loginUserField.setText(savedLogin.isEnabled() && !savedLogin.getUsername().isBlank()
            ? savedLogin.getUsername() : "admin");
        String savedPw = savedLogin.isPasswordSaved() ? savedLogin.getPassword() : "";
        loginPassField.setText(savedPw);

        rememberBox = styledCheck("Remember me on this device");
        rememberBox.setSelected(savedLogin.isEnabled());

        savePasswordBox = styledCheck("Also save my password");
        savePasswordBox.setSelected(savedLogin.isPasswordSaved());
        savePasswordBox.disableProperty().bind(rememberBox.selectedProperty().not());

        Label pwWarning = new Label(
            "Saved passwords are encrypted with a key kept on this machine. That hides "
            + "them from casual reading and from backups — it does not protect them from "
            + "anyone who can already log into this computer as you.");
        pwWarning.setStyle("-fx-text-fill: #344a60; -fx-font-size: 10px;");
        pwWarning.setWrapText(true);
        pwWarning.setMaxWidth(320);

        Hyperlink forget = new Hyperlink("Forget saved login");
        forget.setStyle("-fx-text-fill: #7a8fa6; -fx-font-size: 10px; -fx-padding: 0;");
        forget.setVisible(savedLogin.isEnabled());
        forget.setOnAction(e -> {
            savedLogin.forget();
            loginUserField.clear();
            loginPassField.clear();
            rememberBox.setSelected(false);
            savePasswordBox.setSelected(false);
            forget.setVisible(false);
            status("✓  Saved login cleared.", "#22c55e");
        });

        signInBtn = UiHelper.btnPrimary("AUTHENTICATE  →");
        signInBtn.setMaxWidth(320); signInBtn.setPrefHeight(44);
        signInBtn.setOnAction(e -> doLogin());
        loginPassField.setOnAction(e -> doLogin());
        loginUserField.setOnAction(e -> loginPassField.requestFocus());

        busySpinner = new ProgressIndicator();
        busySpinner.setPrefSize(18, 18);
        busySpinner.setVisible(false);
        busySpinner.setStyle("-fx-progress-color: #f5a623;");

        HBox btnRow = new HBox(10, signInBtn);
        btnRow.setAlignment(Pos.CENTER_LEFT);

        VBox box = new VBox(14,
            field("USERNAME", loginUserField),
            field("PASSWORD", loginPassField),
            new VBox(6, rememberBox, savePasswordBox, pwWarning),
            btnRow,
            new HBox(8, busySpinner, forget));
        ((HBox) box.getChildren().get(4)).setAlignment(Pos.CENTER_LEFT);

        // Focus the password box when a username is already remembered.
        Platform.runLater(() ->
            (loginUserField.getText().isBlank() ? loginUserField : loginPassField).requestFocus());

        return box;
    }

    private VBox buildRegisterForm() {
        TextField userF = UiHelper.textField("Choose a username");
        userF.setMaxWidth(320);
        PasswordField passF = UiHelper.passwordField("Min 8 chars, UPPER + digit + symbol");
        passF.setMaxWidth(320);
        ComboBox<String> roleBox = new ComboBox<>();
        roleBox.getItems().addAll("USER", "AUDITOR", "ADMIN");
        roleBox.setValue("USER");
        roleBox.setMaxWidth(320);

        Label roleHint = new Label(
            "USER sees File Manager and Recovery. AUDITOR sees Overview and Audit Logs. "
            + "ADMIN sees everything.");
        roleHint.setStyle("-fx-text-fill: #344a60; -fx-font-size: 10px;");
        roleHint.setWrapText(true);
        roleHint.setMaxWidth(320);

        Button btn = UiHelper.btnSuccess("CREATE ACCOUNT");
        btn.setMaxWidth(320); btn.setPrefHeight(44);
        btn.setOnAction(e -> doRegister(userF.getText(), passF.getText(), roleBox.getValue()));
        passF.setOnAction(e -> doRegister(userF.getText(), passF.getText(), roleBox.getValue()));

        return new VBox(14, field("USERNAME", userF), field("PASSWORD", passF),
            field("ROLE", roleBox), roleHint, btn);
    }

    // ── Actions ──────────────────────────────────────────────────────

    /**
     * Authentication runs off the UI thread.
     *
     * PBKDF2 at 310,000 iterations plus a 210,000-iteration KEK derivation is
     * roughly half a second of deliberate CPU work. On the JavaFX application
     * thread that reads as the window freezing on every sign-in, which is what
     * v2 did. Here the work moves to a daemon thread and the button shows a
     * spinner instead.
     */
    private void doLogin() {
        String u = loginUserField.getText();
        String p = loginPassField.getText();

        if (u == null || u.isBlank()) { status("✗  Enter a username.", "#ef4444"); return; }
        if (p == null || p.isEmpty()) { status("✗  Enter a password.", "#ef4444"); return; }

        setBusy(true, "DERIVING KEYS…");

        Thread worker = new Thread(() -> {
            try {
                String token = AppState.get().getAuthManager().login(u, p);
                User user = AppState.get().getAuthManager().getSessionUser(token);
                AppState.get().setSession(token, user);

                if (rememberBox.isSelected()) {
                    savedLogin.remember(u, p, savePasswordBox.isSelected());
                } else {
                    savedLogin.forget();
                }

                Platform.runLater(() -> {
                    setBusy(false, null);
                    onLoginSuccess.accept(user);
                });
            } catch (Exception ex) {
                Platform.runLater(() -> {
                    setBusy(false, null);
                    status("✗  " + ex.getMessage(), "#ef4444");
                    loginPassField.clear();
                    loginPassField.requestFocus();
                });
            }
        }, "login-worker");
        worker.setDaemon(true);
        worker.start();
    }

    private void doRegister(String u, String p, String r) {
        setBusy(true, "HASHING PASSWORD…");
        Thread worker = new Thread(() -> {
            try {
                AppState.get().getAuthManager().registerUser(u, p, Role.valueOf(r));
                Platform.runLater(() -> {
                    setBusy(false, null);
                    status("✓  Account created. Switch to SIGN IN to continue.", "#22c55e");
                });
            } catch (Exception ex) {
                Platform.runLater(() -> {
                    setBusy(false, null);
                    status("✗  " + ex.getMessage(), "#ef4444");
                });
            }
        }, "register-worker");
        worker.setDaemon(true);
        worker.start();
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private void setBusy(boolean busy, String message) {
        signInBtn.setDisable(busy);
        busySpinner.setVisible(busy);
        if (busy && message != null) status(message, "#f5a623");
    }

    private void status(String m, String c) {
        statusLabel.setText(m);
        statusLabel.setStyle("-fx-font-size: 12px; -fx-text-fill: " + c
            + "; -fx-font-family: 'Courier New', monospace;");
    }

    private CheckBox styledCheck(String text) {
        CheckBox cb = new CheckBox(text);
        cb.setStyle("-fx-text-fill: #7a8fa6; -fx-font-size: 11px;");
        cb.setMaxWidth(320);
        return cb;
    }

    private VBox field(String lbl, javafx.scene.Node input) {
        Label l = new Label(lbl);
        l.setStyle("-fx-font-size: 10px; -fx-font-weight: bold; -fx-text-fill: #344a60;"
            + "-fx-font-family: 'Courier New', monospace; -fx-padding: 0 0 4 0;");
        VBox box = new VBox(4, l, input);
        box.setMaxWidth(320);
        return box;
    }
}
