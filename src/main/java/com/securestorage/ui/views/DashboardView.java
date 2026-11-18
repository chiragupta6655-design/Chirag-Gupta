package com.securestorage.ui.views;

import com.securestorage.auth.Role;
import com.securestorage.auth.User;
import com.securestorage.ui.AppState;
import com.securestorage.ui.Theme;
import com.securestorage.ui.components.UiHelper;
import javafx.animation.*;
import javafx.geometry.*;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.effect.DropShadow;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import javafx.util.Duration;

import java.util.*;

public class DashboardView extends BorderPane {

    /** One entry in the sidebar. */
    private record NavItem(String icon, String title, EnumSet<Role> visibleTo) {}

    /**
     * ── Role-based navigation ───────────────────────────────────────
     * The menu is built from the signed-in user's role, so a USER never sees a
     * page they cannot act on.
     *
     *   ADMIN    every page
     *   USER     File Manager, Recovery
     *   AUDITOR  Overview, Audit Logs
     *
     * This is presentation-layer filtering and nothing more. Hiding a button is
     * not access control — every operation behind these pages still goes
     * through AuthManager.requirePermission on the server side of the call.
     * If the two ever disagree, the permission check is the one that decides.
     */
    private static final List<NavItem> NAV = List.of(
        new NavItem("⬡", "Overview",         EnumSet.of(Role.ADMIN, Role.AUDITOR)),
        new NavItem("◈", "File Manager",     EnumSet.of(Role.ADMIN, Role.USER)),
        new NavItem("◎", "Encryption Lab",   EnumSet.of(Role.ADMIN)),
        new NavItem("◉", "User Manager",     EnumSet.of(Role.ADMIN)),
        new NavItem("▲", "Attack Simulator", EnumSet.of(Role.ADMIN)),
        new NavItem("≡", "Audit Logs",       EnumSet.of(Role.ADMIN, Role.AUDITOR)),
        new NavItem("◆", "Recovery",         EnumSet.of(Role.ADMIN, Role.USER))
    );

    private final Runnable onLogout;
    private final StackPane contentArea = new StackPane();
    private final Map<String, Node>   pageCache = new LinkedHashMap<>();
    private final Map<String, Button> navButtons = new LinkedHashMap<>();

    private Button activeNavBtn;

    public DashboardView(Runnable onLogout) {
        this.onLogout = onLogout;
        getStylesheets().add("data:text/css," + Theme.STYLESHEET.replace("\n", " "));
        setStyle("-fx-background-color: #080c14;");
        setLeft(buildSidebar());
        setCenter(buildContent());

        String landing = navButtons.keySet().stream().findFirst().orElse("File Manager");
        showPage(landing);
    }

    /** Pages this role is allowed to see. */
    private List<NavItem> visibleNav() {
        Role role = AppState.get().getCurrentUser().getRole();
        return NAV.stream().filter(n -> n.visibleTo().contains(role)).toList();
    }

    private VBox buildSidebar() {
        Label iconLbl = new Label("⬡");
        iconLbl.setStyle("-fx-font-size: 24px; -fx-text-fill: #f5a623;");
        DropShadow glow = new DropShadow();
        glow.setColor(Color.web("#f5a623", 0.7)); glow.setRadius(14); glow.setSpread(0.2);
        iconLbl.setEffect(glow);

        Label titleLbl = new Label("SECUREVAULT");
        titleLbl.setStyle(
            "-fx-font-size: 13px; -fx-font-weight: bold; -fx-text-fill: #f0f4f8;" +
            "-fx-font-family: 'Palatino Linotype', serif; -fx-letter-spacing: 2;");

        Label verLbl = new Label("v3.0.0");
        verLbl.setStyle("-fx-font-size: 9px; -fx-text-fill: #344a60; -fx-font-family: 'Courier New';");

        HBox logo = new HBox(12, iconLbl, new VBox(2, titleLbl, verLbl));
        logo.setAlignment(Pos.CENTER_LEFT);
        logo.setPadding(new Insets(22, 20, 22, 22));

        VBox nav = new VBox(1);
        for (NavItem item : visibleNav()) {
            Button btn = buildNavBtn(item.icon() + "   " + item.title(), item.title());
            navButtons.put(item.title(), btn);
            nav.getChildren().add(btn);
        }
        VBox.setVgrow(nav, Priority.ALWAYS);

        VBox sidebar = new VBox(logo, UiHelper.divider(), nav,
            UiHelper.spacer(), UiHelper.divider(), buildUserCard());
        sidebar.getStyleClass().add("sidebar");
        sidebar.setPrefWidth(220); sidebar.setMinWidth(220); sidebar.setMaxWidth(220);
        return sidebar;
    }

    private Button buildNavBtn(String label, String pageName) {
        Button btn = new Button(label);
        btn.getStyleClass().add("nav-btn");
        btn.setMaxWidth(Double.MAX_VALUE);
        btn.setAlignment(Pos.CENTER_LEFT);
        btn.setOnAction(e -> showPage(pageName));
        return btn;
    }

    private void setActiveNav(Button btn) {
        if (activeNavBtn != null) activeNavBtn.getStyleClass().remove("nav-btn-active");
        if (btn != null) btn.getStyleClass().add("nav-btn-active");
        activeNavBtn = btn;
    }

    private VBox buildUserCard() {
        User user = AppState.get().getCurrentUser();
        String roleColor = switch (user.getRole()) {
            case ADMIN   -> Theme.ACCENT_AMBER;
            case AUDITOR -> Theme.ACCENT_PURPLE;
            default      -> Theme.ACCENT_GREEN;
        };

        Circle av = new Circle(16);
        av.setFill(Color.web(roleColor, 0.15));
        av.setStroke(Color.web(roleColor, 0.6));
        av.setStrokeWidth(1.5);

        Label init = new Label(user.getUsername().substring(0, 1).toUpperCase());
        init.setStyle("-fx-font-weight: bold; -fx-font-size: 13px; -fx-text-fill: " + roleColor + ";");
        StackPane avatar = new StackPane(av, init);

        Label nameLbl = new Label(user.getUsername().toUpperCase());
        nameLbl.setStyle("-fx-font-weight: bold; -fx-text-fill: #f0f4f8; -fx-font-size: 11px; -fx-font-family: 'Courier New';");
        Label roleLbl = UiHelper.statusBadge(user.getRole().name(), roleColor);

        Button logoutBtn = new Button("SIGN OUT");
        logoutBtn.setStyle("-fx-background-color: transparent; -fx-text-fill: #344a60; -fx-font-size: 10px; -fx-cursor: hand; -fx-padding: 0; -fx-font-family: 'Courier New';");
        logoutBtn.setOnAction(e -> onLogout.run());
        logoutBtn.setOnMouseEntered(e -> logoutBtn.setStyle(logoutBtn.getStyle().replace("#344a60", "#ef4444")));
        logoutBtn.setOnMouseExited(e -> logoutBtn.setStyle(logoutBtn.getStyle().replace("#ef4444", "#344a60")));

        HBox row = new HBox(10, avatar, new VBox(3, nameLbl, roleLbl), UiHelper.spacer(), logoutBtn);
        row.setAlignment(Pos.CENTER_LEFT);
        row.setPadding(new Insets(14, 16, 14, 16));
        return new VBox(row);
    }

    private StackPane buildContent() {
        contentArea.setStyle("-fx-background-color: #080c14;");
        return contentArea;
    }

    private void showPage(String name) {
        setActiveNav(navButtons.get(name));

        Node page = pageCache.computeIfAbsent(name, this::createPage);
        contentArea.getChildren().setAll(page);

        page.setTranslateX(16); page.setOpacity(0);
        new Timeline(
            new KeyFrame(Duration.millis(0),
                new KeyValue(page.translateXProperty(), 16),
                new KeyValue(page.opacityProperty(), 0)),
            new KeyFrame(Duration.millis(250),
                new KeyValue(page.translateXProperty(), 0, Interpolator.EASE_OUT),
                new KeyValue(page.opacityProperty(), 1, Interpolator.EASE_OUT))
        ).play();
    }

    private Node createPage(String name) {
        // Second gate: even if a page name were reached some other way, a role
        // that is not allowed to see it gets a notice instead of the page.
        boolean permitted = visibleNav().stream().anyMatch(n -> n.title().equals(name));
        if (!permitted) return restrictedNotice(name);

        return switch (name) {
            case "Overview"         -> new OverviewView();
            case "File Manager"     -> new FileManagerView();
            case "Encryption Lab"   -> new EncryptionLabView();
            case "User Manager"     -> new UserManagerView();
            case "Attack Simulator" -> new AttackSimulatorView();
            case "Audit Logs"       -> new AuditLogView();
            case "Recovery"         -> new RecoveryView();
            default                 -> new Label("Page: " + name);
        };
    }

    private Node restrictedNotice(String name) {
        Label icon = new Label("⚠");
        icon.setStyle("-fx-font-size: 40px; -fx-text-fill: #ef4444;");
        Label title = UiHelper.h2("Access restricted");
        Label body = UiHelper.labelSecondary(
            "Your role (" + AppState.get().getCurrentUser().getRole()
            + ") does not have access to " + name + ".");
        VBox box = new VBox(12, icon, title, body);
        box.setAlignment(Pos.CENTER);
        box.setPadding(new Insets(60));
        return box;
    }
}
