package com.securestorage.ui;

public final class Theme {
    private Theme() {}
    public static final String BG_DEEP      = "#080c14";
    public static final String BG_SURFACE   = "#0c1221";
    public static final String BG_ELEVATED  = "#111d2e";
    public static final String BG_HOVER     = "#162338";
    public static final String ACCENT_AMBER  = "#f5a623";
    public static final String ACCENT_BLUE   = "#0ea5e9";
    public static final String ACCENT_GREEN  = "#22c55e";
    public static final String ACCENT_RED    = "#ef4444";
    public static final String ACCENT_PURPLE = "#8b5cf6";
    public static final String ACCENT_GOLD   = "#fbbf24";
    public static final String ACCENT_CYAN   = "#f5a623";
    public static final String TEXT_PRIMARY   = "#f0f4f8";
    public static final String TEXT_SECONDARY = "#7a8fa6";
    public static final String TEXT_MUTED     = "#344a60";
    public static final String TEXT_DATA      = "#f5a623";
    public static final String BORDER         = "#162338";
    public static final String BORDER_GLOW    = "#f5a62355";

    public static final String STYLESHEET = buildStylesheet();

    private static String buildStylesheet() {
        return
        ".root { -fx-background-color: #080c14; -fx-font-family: 'Trebuchet MS', 'Segoe UI', sans-serif; -fx-font-size: 13px; }" +
        ".label { -fx-text-fill: #f0f4f8; }" +
        ".label-secondary { -fx-text-fill: #7a8fa6; }" +
        ".label-muted     { -fx-text-fill: #344a60; }" +
        ".label-accent    { -fx-text-fill: #f5a623; }" +
        ".label-blue      { -fx-text-fill: #0ea5e9; }" +
        ".label-success   { -fx-text-fill: #22c55e; }" +
        ".label-danger    { -fx-text-fill: #ef4444; }" +
        ".label-warning   { -fx-text-fill: #f5a623; }" +
        ".label-gold      { -fx-text-fill: #fbbf24; }" +
        ".label-code { -fx-font-family: 'Courier New', monospace; -fx-text-fill: #f5a623; -fx-font-size: 12px; }" +
        ".h1 { -fx-font-size: 30px; -fx-font-weight: bold; -fx-text-fill: #f0f4f8; -fx-font-family: 'Palatino Linotype', 'Georgia', serif; }" +
        ".h2 { -fx-font-size: 20px; -fx-font-weight: bold; -fx-text-fill: #f0f4f8; }" +
        ".h3 { -fx-font-size: 13px; -fx-font-weight: bold; -fx-text-fill: #f5a623; -fx-font-family: 'Courier New', monospace; }" +
        ".btn-primary { -fx-background-color: #f5a623; -fx-text-fill: #080c14; -fx-font-weight: bold; -fx-font-size: 13px; -fx-padding: 10 26 10 26; -fx-cursor: hand; -fx-background-radius: 4px; }" +
        ".btn-primary:hover { -fx-background-color: #fbbf24; -fx-effect: dropshadow(gaussian, #f5a62388, 14, 0.3, 0, 0); }" +
        ".btn-primary:pressed { -fx-background-color: #d4891a; }" +
        ".btn-danger { -fx-background-color: transparent; -fx-text-fill: #ef4444; -fx-font-weight: bold; -fx-padding: 9 18 9 18; -fx-cursor: hand; -fx-background-radius: 4px; -fx-border-color: #ef4444; -fx-border-width: 1px; -fx-border-radius: 4px; }" +
        ".btn-danger:hover { -fx-background-color: #ef444422; -fx-effect: dropshadow(gaussian, #ef444455, 10, 0.2, 0, 0); }" +
        ".btn-ghost { -fx-background-color: transparent; -fx-text-fill: #7a8fa6; -fx-padding: 9 18 9 18; -fx-cursor: hand; -fx-background-radius: 4px; -fx-border-color: #162338; -fx-border-radius: 4px; -fx-border-width: 1px; }" +
        ".btn-ghost:hover { -fx-background-color: #162338; -fx-text-fill: #f0f4f8; }" +
        ".btn-success { -fx-background-color: transparent; -fx-text-fill: #22c55e; -fx-font-weight: bold; -fx-padding: 9 18 9 18; -fx-cursor: hand; -fx-background-radius: 4px; -fx-border-color: #22c55e; -fx-border-width: 1px; -fx-border-radius: 4px; }" +
        ".btn-success:hover { -fx-background-color: #22c55e22; -fx-effect: dropshadow(gaussian, #22c55e55, 10, 0.2, 0, 0); }" +
        ".card { -fx-background-color: #0c1221; -fx-background-radius: 6px; -fx-border-color: #162338; -fx-border-width: 1px; -fx-border-radius: 6px; -fx-padding: 20px; }" +
        ".card-accent { -fx-background-color: #0c1221; -fx-background-radius: 6px; -fx-border-color: #f5a62355; -fx-border-width: 1px; -fx-border-radius: 6px; -fx-padding: 20px; -fx-effect: dropshadow(gaussian, #f5a62322, 16, 0.1, 0, 0); }" +
        ".text-field, .password-field, .text-area { -fx-background-color: #111d2e; -fx-text-fill: #f0f4f8; -fx-prompt-text-fill: #344a60; -fx-border-color: #162338; -fx-border-width: 1px; -fx-border-radius: 4px; -fx-background-radius: 4px; -fx-padding: 9 13 9 13; -fx-font-size: 13px; }" +
        ".text-field:focused, .password-field:focused, .text-area:focused { -fx-border-color: #f5a623; -fx-background-color: #14213a; -fx-effect: dropshadow(gaussian, #f5a62333, 12, 0.15, 0, 0); }" +
        ".table-view { -fx-background-color: #0c1221; -fx-border-color: #162338; -fx-border-radius: 6px; -fx-background-radius: 6px; }" +
        ".table-view .column-header-background { -fx-background-color: #080c14; }" +
        ".table-view .column-header .label { -fx-text-fill: #f5a623; -fx-font-weight: bold; -fx-font-size: 10px; -fx-font-family: 'Courier New', monospace; }" +
        ".table-row-cell { -fx-background-color: #0c1221; -fx-border-color: transparent transparent #162338 transparent; -fx-border-width: 0 0 1px 0; }" +
        ".table-row-cell:odd { -fx-background-color: #0a1019; }" +
        ".table-row-cell:hover { -fx-background-color: #111d2e; }" +
        ".table-row-cell:selected { -fx-background-color: #f5a62318; }" +
        ".table-row-cell .text { -fx-fill: #f0f4f8; }" +
        ".table-view .placeholder .label { -fx-text-fill: #344a60; }" +
        ".sidebar { -fx-background-color: #080c14; -fx-border-color: #162338; -fx-border-width: 0 1px 0 0; }" +
        ".nav-btn { -fx-background-color: transparent; -fx-text-fill: #7a8fa6; -fx-font-size: 13px; -fx-padding: 13 22 13 22; -fx-cursor: hand; -fx-alignment: center-left; -fx-min-width: 210px; -fx-background-radius: 0; }" +
        ".nav-btn:hover { -fx-background-color: #0c1221; -fx-text-fill: #f0f4f8; }" +
        ".nav-btn-active { -fx-background-color: #111d2e; -fx-text-fill: #f5a623; -fx-font-weight: bold; -fx-border-color: #f5a623 transparent transparent transparent; -fx-border-width: 0 0 0 2px; }" +
        ".tab-pane .tab-header-area .tab-header-background { -fx-background-color: #080c14; }" +
        ".tab-pane .tab { -fx-background-color: #0c1221; -fx-padding: 9 18; }" +
        ".tab-pane .tab .tab-label { -fx-text-fill: #7a8fa6; }" +
        ".tab-pane .tab:selected { -fx-background-color: #111d2e; }" +
        ".tab-pane .tab:selected .tab-label { -fx-text-fill: #f5a623; }" +
        ".combo-box { -fx-background-color: #111d2e; -fx-border-color: #162338; -fx-border-radius: 4px; -fx-background-radius: 4px; }" +
        ".combo-box .list-cell { -fx-text-fill: #f0f4f8; -fx-background-color: #111d2e; }" +
        ".combo-box-popup .list-view { -fx-background-color: #111d2e; }" +
        ".combo-box-popup .list-cell:hover { -fx-background-color: #f5a62318; }" +
        ".combo-box .arrow { -fx-background-color: #7a8fa6; }" +
        ".progress-bar .track { -fx-background-color: #111d2e; -fx-background-radius: 2px; }" +
        ".progress-bar .bar { -fx-background-color: linear-gradient(to right, #d4891a, #f5a623, #fbbf24); -fx-background-radius: 2px; -fx-background-insets: 0; -fx-effect: dropshadow(gaussian, #f5a62388, 6, 0.4, 0, 0); }" +
        ".scroll-bar { -fx-background-color: #080c14; }" +
        ".scroll-bar .thumb { -fx-background-color: #162338; -fx-background-radius: 2px; }" +
        ".scroll-bar .thumb:hover { -fx-background-color: #1e3050; }" +
        ".scroll-bar .increment-button, .scroll-bar .decrement-button { -fx-background-color: transparent; }" +
        ".scroll-bar .increment-arrow, .scroll-bar .decrement-arrow { -fx-background-color: #344a60; }" +
        ".separator .line { -fx-border-color: #162338; }" +
        ".toggle-button { -fx-background-color: transparent; -fx-text-fill: #7a8fa6; -fx-padding: 9 22; -fx-cursor: hand; -fx-background-radius: 4px; }" +
        ".toggle-button:selected { -fx-background-color: #f5a62318; -fx-text-fill: #f5a623; -fx-font-weight: bold; }" +
        ".toggle-button:hover { -fx-background-color: #0c1221; -fx-text-fill: #f0f4f8; }";
    }
}
