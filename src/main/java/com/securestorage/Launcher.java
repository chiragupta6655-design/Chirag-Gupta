package com.securestorage;

import com.securestorage.ui.SecureStorageApp;

/**
 * Entry point for the packaged JAR.
 *
 * ── Why this class exists ───────────────────────────────────────────
 * When the main class extends javafx.application.Application, the JavaFX
 * launcher checks at startup that the JavaFX runtime was loaded as a set of
 * named modules. A shaded fat JAR puts those classes on the classpath instead,
 * so the check fails with:
 *
 *     Error: JavaFX runtime components are missing, and are required to run
 *
 * even though every class it needs is right there in the JAR. Routing through a
 * plain class that does not extend Application skips that check, and
 * Application.launch() then starts normally. This is the reason `java -jar`
 * works here without --module-path or --add-modules.
 */
public final class Launcher {

    public static void main(String[] args) {
        SecureStorageApp.main(args);
    }
}
