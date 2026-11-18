package com.securestorage.ui.components;

import com.securestorage.ui.Theme;
import javafx.geometry.*;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.*;
import javafx.scene.effect.DropShadow;

public final class UiHelper {
    private UiHelper() {}

    public static Label h1(String t) { Label l=new Label(t); l.getStyleClass().add("h1"); return l; }
    public static Label h2(String t) { Label l=new Label(t); l.getStyleClass().add("h2"); return l; }
    public static Label h3(String t) { Label l=new Label(t); l.getStyleClass().add("h3"); return l; }
    public static Label label(String t) { return new Label(t); }
    public static Label labelSecondary(String t) { Label l=new Label(t); l.getStyleClass().add("label-secondary"); return l; }
    public static Label labelCode(String t) { Label l=new Label(t); l.getStyleClass().add("label-code"); return l; }
    public static Label labelAccent(String t) { Label l=new Label(t); l.getStyleClass().add("label-accent"); return l; }
    public static Label labelSuccess(String t) { Label l=new Label(t); l.getStyleClass().add("label-success"); return l; }
    public static Label labelDanger(String t) { Label l=new Label(t); l.getStyleClass().add("label-danger"); return l; }
    public static Label labelWarning(String t) { Label l=new Label(t); l.getStyleClass().add("label-warning"); return l; }

    public static Button btnPrimary(String t) { Button b=new Button(t); b.getStyleClass().add("btn-primary"); return b; }
    public static Button btnDanger(String t) { Button b=new Button(t); b.getStyleClass().add("btn-danger"); return b; }
    public static Button btnGhost(String t) { Button b=new Button(t); b.getStyleClass().add("btn-ghost"); return b; }
    public static Button btnSuccess(String t) { Button b=new Button(t); b.getStyleClass().add("btn-success"); return b; }

    public static TextField textField(String p) { TextField tf=new TextField(); tf.setPromptText(p); return tf; }
    public static PasswordField passwordField(String p) { PasswordField pf=new PasswordField(); pf.setPromptText(p); return pf; }

    public static VBox card(Node... c) { VBox b=new VBox(12,c); b.getStyleClass().add("card"); return b; }
    public static VBox cardAccent(Node... c) { VBox b=new VBox(12,c); b.getStyleClass().add("card-accent"); return b; }

    public static HBox hbox(int sp, Node... c) {
        HBox b=new HBox(sp,c); b.setAlignment(Pos.CENTER_LEFT); return b;
    }
    public static VBox vbox(int sp, Node... c) { return new VBox(sp,c); }

    public static Region spacer() {
        Region r=new Region();
        HBox.setHgrow(r,Priority.ALWAYS);
        VBox.setVgrow(r,Priority.ALWAYS);
        return r;
    }

    public static Region divider() {
        Region r=new Region(); r.setPrefHeight(1); r.setMaxWidth(Double.MAX_VALUE);
        r.setStyle("-fx-background-color: #162338;"); return r;
    }

    public static Separator separator() { return new Separator(); }

    /** Luxury stat card with large amber number and glow effect */
    public static VBox statCard(String value, String title, String accentColor) {
        Label valLbl = new Label(value);
        valLbl.setStyle(
            "-fx-font-size: 36px;" +
            "-fx-font-weight: bold;" +
            "-fx-text-fill: " + accentColor + ";" +
            "-fx-font-family: 'Courier New', monospace;");

        // Glow effect on the number
        DropShadow glow = new DropShadow();
        glow.setColor(Color.web(accentColor, 0.5));
        glow.setRadius(12);
        glow.setSpread(0.1);
        valLbl.setEffect(glow);

        // Thin accent line at top
        Region topLine = new Region();
        topLine.setPrefHeight(2);
        topLine.setMaxWidth(Double.MAX_VALUE);
        topLine.setStyle("-fx-background-color: " + accentColor + ";");

        Label titleLbl = new Label(title.toUpperCase());
        titleLbl.setStyle(
            "-fx-text-fill: #7a8fa6;" +
            "-fx-font-size: 10px;" +
            "-fx-font-family: 'Courier New', monospace;" +
            "-fx-letter-spacing: 1;");

        VBox card = new VBox(0, topLine, new VBox(14, valLbl, titleLbl));
        ((VBox)card.getChildren().get(1)).setPadding(new Insets(14, 18, 14, 18));
        card.setStyle(
            "-fx-background-color: #0c1221;" +
            "-fx-background-radius: 6px;" +
            "-fx-border-color: #162338;" +
            "-fx-border-width: 1px;" +
            "-fx-border-radius: 6px;");
        card.setMinWidth(148);
        return card;
    }

    /** Compact status badge */
    public static Label statusBadge(String text, String color) {
        Label l = new Label(text.toUpperCase());
        l.setStyle(
            "-fx-background-color: " + color + "18;" +
            "-fx-text-fill: " + color + ";" +
            "-fx-background-radius: 3px;" +
            "-fx-padding: 3 8 3 8;" +
            "-fx-font-size: 10px;" +
            "-fx-font-weight: bold;" +
            "-fx-font-family: 'Courier New', monospace;");
        return l;
    }

    public static VBox sectionHeader(String title, String subtitle) {
        Label t = h2(title);
        Label s = labelSecondary(subtitle);
        s.setStyle("-fx-font-size: 13px; -fx-text-fill: #7a8fa6;");
        return new VBox(5, t, s);
    }

    public static ScrollPane scrollPane(Node content) {
        ScrollPane sp = new ScrollPane(content);
        sp.setFitToWidth(true);
        sp.setStyle("-fx-background: transparent; -fx-background-color: transparent; -fx-border-color: transparent;");
        sp.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);
        return sp;
    }

    public static TextArea consoleArea() {
        TextArea ta = new TextArea();
        ta.setEditable(false);
        ta.setStyle(
            "-fx-font-family: 'Courier New', monospace;" +
            "-fx-font-size: 12px;" +
            "-fx-text-fill: #f5a623;" +
            "-fx-background-color: #040709;" +
            "-fx-control-inner-background: #040709;" +
            "-fx-border-color: #162338;" +
            "-fx-border-radius: 4px;" +
            "-fx-background-radius: 4px;");
        ta.setPrefRowCount(14);
        VBox.setVgrow(ta, Priority.ALWAYS);
        return ta;
    }
}
