package com.securestorage.ui.views;

import com.securestorage.auth.User;
import com.securestorage.logging.AuditLogger;
import com.securestorage.ui.AppState;
import com.securestorage.ui.Theme;
import com.securestorage.ui.components.UiHelper;
import javafx.animation.*;
import javafx.geometry.*;
import javafx.scene.control.Label;
import javafx.scene.effect.DropShadow;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.Rectangle;
import javafx.util.Duration;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class OverviewView extends VBox {

    public OverviewView() {
        super(28);
        setPadding(new Insets(36));
        setStyle("-fx-background-color: #080c14;");
        build();
    }

    private void build() {
        User user = AppState.get().getCurrentUser();

        // ── Header row ───────────────────────────────────────────
        Label greeting = new Label("SECUREVAULT");
        greeting.setStyle(
            "-fx-font-size: 28px; -fx-font-weight: bold; -fx-text-fill: #f0f4f8;" +
            "-fx-font-family: 'Palatino Linotype', 'Georgia', serif;");
        DropShadow titleGlow = new DropShadow();
        titleGlow.setColor(Color.web("#f5a623", 0.25));
        titleGlow.setRadius(20);
        greeting.setEffect(titleGlow);

        Label userInfo = new Label("SESSION: " + user.getUsername().toUpperCase() + "  ·  ROLE: " + user.getRole());
        userInfo.setStyle("-fx-font-size: 11px; -fx-text-fill: #344a60; -fx-font-family: 'Courier New', monospace;");

        Label time = new Label(LocalDateTime.now().format(
            DateTimeFormatter.ofPattern("EEE dd MMM yyyy  HH:mm:ss")));
        time.setStyle("-fx-font-size: 11px; -fx-text-fill: #344a60; -fx-font-family: 'Courier New', monospace;");

        HBox headerRow = UiHelper.hbox(0, new VBox(4, greeting, userInfo), UiHelper.spacer(), time);

        // Amber accent bar
        Region accentBar = new Region();
        accentBar.setPrefHeight(1); accentBar.setMaxWidth(Double.MAX_VALUE);
        accentBar.setStyle("-fx-background-color: linear-gradient(to right, #f5a623, #f5a62300);");

        // ── Stats row ─────────────────────────────────────────────
        int files   = AppState.get().getFileStorage().getFileCount();
        int users   = (int) AppState.get().getAuthManager().getAllUsers().stream().filter(User::isActive).count();
        int logs    = AppState.get().getAuditLogger().getAllLogs().size();
        int secEvts = AppState.get().getAuditLogger().getSecurityEvents().size();

        HBox stats = new HBox(14,
            UiHelper.statCard(String.valueOf(files),   "ENCRYPTED FILES",  Theme.ACCENT_AMBER),
            UiHelper.statCard(String.valueOf(users),   "ACTIVE USERS",     Theme.ACCENT_GREEN),
            UiHelper.statCard(String.valueOf(logs),    "AUDIT EVENTS",     Theme.ACCENT_BLUE),
            UiHelper.statCard(String.valueOf(secEvts), "SECURITY ALERTS",  Theme.ACCENT_RED)
        );

        // Animate stats in with stagger
        for (int i = 0; i < stats.getChildren().size(); i++) {
            javafx.scene.Node n = stats.getChildren().get(i);
            n.setOpacity(0); n.setTranslateY(12);
            Timeline tl = new Timeline(
                new KeyFrame(Duration.millis(100 + i * 80),
                    new KeyValue(n.opacityProperty(), 0),
                    new KeyValue(n.translateYProperty(), 12)),
                new KeyFrame(Duration.millis(350 + i * 80),
                    new KeyValue(n.opacityProperty(), 1, Interpolator.EASE_OUT),
                    new KeyValue(n.translateYProperty(), 0, Interpolator.EASE_OUT))
            );
            tl.play();
        }

        // ── Content row ───────────────────────────────────────────
        VBox activity = buildActivityCard();
        VBox statusCard = buildStatusCard();
        HBox.setHgrow(activity, Priority.ALWAYS);
        HBox content = new HBox(14, activity, statusCard);
        VBox.setVgrow(content, Priority.ALWAYS);

        getChildren().addAll(headerRow, accentBar, stats, content);
    }

    private VBox buildActivityCard() {
        Label title = UiHelper.h3("── RECENT ACTIVITY LOG ──");

        List<AuditLogger.LogEntry> logs = AppState.get().getAuditLogger().getAllLogs();
        VBox rows = new VBox(6);

        if (logs.isEmpty()) {
            Label empty = new Label("NO EVENTS RECORDED");
            empty.setStyle("-fx-text-fill: #344a60; -fx-font-family: 'Courier New'; -fx-font-size: 12px;");
            rows.getChildren().add(empty);
        } else {
            var recent = logs.subList(Math.max(0, logs.size() - 9), logs.size());
            for (int i = recent.size() - 1; i >= 0; i--)
                rows.getChildren().add(activityRow(recent.get(i)));
        }

        VBox card = new VBox(16, title, UiHelper.divider(), UiHelper.scrollPane(rows));
        card.setStyle(
            "-fx-background-color: #0c1221;" +
            "-fx-background-radius: 6;" +
            "-fx-border-color: #162338;" +
            "-fx-border-width: 1;" +
            "-fx-border-radius: 6;" +
            "-fx-padding: 20;");
        VBox.setVgrow(card, Priority.ALWAYS);
        return card;
    }

    private HBox activityRow(AuditLogger.LogEntry e) {
        String color = actionColor(e.action());
        Label badge = UiHelper.statusBadge(abbrev(e.action()), color);
        badge.setMinWidth(100);

        Label user = new Label(e.username());
        user.setStyle("-fx-text-fill: #7a8fa6; -fx-font-size: 11px; -fx-font-family: 'Courier New'; -fx-min-width: 70;");

        Label msg = new Label(truncate(e.message(), 44));
        msg.setStyle("-fx-text-fill: #7a8fa6; -fx-font-size: 11px;");

        Label ts = new Label(e.timestamp().format(DateTimeFormatter.ofPattern("HH:mm:ss")));
        ts.setStyle("-fx-text-fill: #344a60; -fx-font-size: 10px; -fx-font-family: 'Courier New';");

        HBox row = new HBox(10, badge, user, msg, UiHelper.spacer(), ts);
        row.setAlignment(Pos.CENTER_LEFT);
        row.setPadding(new Insets(5, 8, 5, 8));
        row.setStyle("-fx-background-color: #080c14; -fx-background-radius: 4;");
        return row;
    }

    private VBox buildStatusCard() {
        Label title = UiHelper.h3("── SYSTEM STATUS ──");

        VBox items = new VBox(10,
            statusRow("AES-256-GCM",          "ACTIVE", Theme.ACCENT_GREEN),
            statusRow("RSA-2048-OAEP",         "ACTIVE", Theme.ACCENT_GREEN),
            statusRow("RBAC ENFORCEMENT",      "ACTIVE", Theme.ACCENT_GREEN),
            statusRow("WAL TRANSACTION LOG",   "ACTIVE", Theme.ACCENT_GREEN),
            statusRow("CHECKPOINT RECOVERY",   "ACTIVE", Theme.ACCENT_GREEN),
            statusRow("INPUT VALIDATION",      "ACTIVE", Theme.ACCENT_GREEN),
            statusRow("PBKDF2-SHA256",         "ACTIVE", Theme.ACCENT_GREEN)
        );

        Label cryptoLbl = new Label("── CRYPTO PARAMETERS ──");
        cryptoLbl.setStyle("-fx-font-size: 10px; -fx-text-fill: #f5a623; -fx-font-family: 'Courier New';");

        VBox params = new VBox(5,
            paramRow("CIPHER",      "AES-256-GCM"),
            paramRow("KEY-WRAP",    "RSA-2048-OAEP"),
            paramRow("IV-LEN",      "96-bit / random"),
            paramRow("KDF",         "PBKDF2-SHA256"),
            paramRow("ITERATIONS",  "310,000"),
            paramRow("ROLE",        AppState.get().getCurrentUser().getRole().name())
        );
        params.setStyle("-fx-background-color: #080c14; -fx-background-radius: 4; -fx-padding: 12;");

        VBox card = new VBox(16, title, UiHelper.divider(), items, UiHelper.divider(), cryptoLbl, params);
        card.setStyle(
            "-fx-background-color: #0c1221;" +
            "-fx-background-radius: 6;" +
            "-fx-border-color: #f5a62333;" +
            "-fx-border-width: 1;" +
            "-fx-border-radius: 6;" +
            "-fx-padding: 20;");
        card.setPrefWidth(295); card.setMaxWidth(295);
        return card;
    }

    private HBox statusRow(String name, String status, String color) {
        Label n = new Label(name);
        n.setStyle("-fx-text-fill: #7a8fa6; -fx-font-size: 11px; -fx-font-family: 'Courier New';");
        HBox.setHgrow(n, Priority.ALWAYS);
        Label s = UiHelper.statusBadge(status, color);
        HBox row = new HBox(8, n, UiHelper.spacer(), s);
        row.setAlignment(Pos.CENTER_LEFT);
        return row;
    }

    private HBox paramRow(String key, String val) {
        Label k = new Label(key);
        k.setStyle("-fx-text-fill: #344a60; -fx-font-size: 10px; -fx-font-family: 'Courier New'; -fx-min-width: 80;");
        Label v = new Label(val);
        v.setStyle("-fx-text-fill: #f5a623; -fx-font-size: 10px; -fx-font-family: 'Courier New';");
        return new HBox(8, k, v);
    }

    private String actionColor(String a) {
        if (a.contains("FAIL") || a.contains("DENIED")) return Theme.ACCENT_RED;
        if (a.contains("LOGIN") || a.contains("REGISTER")) return Theme.ACCENT_BLUE;
        if (a.contains("UPLOAD") || a.contains("DOWNLOAD")) return Theme.ACCENT_GREEN;
        if (a.contains("DELETE")) return Theme.ACCENT_AMBER;
        return Theme.ACCENT_PURPLE;
    }

    private String abbrev(String a) {
        return a.length() > 12 ? a.substring(0, 12) : a;
    }

    private String truncate(String s, int max) {
        return s != null && s.length() > max ? s.substring(0, max) + "…" : s;
    }
}
