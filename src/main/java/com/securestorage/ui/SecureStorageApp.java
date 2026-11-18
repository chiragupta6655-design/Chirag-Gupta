package com.securestorage.ui;

import com.securestorage.crypto.pqc.PqcEngine;
import com.securestorage.ui.views.DashboardView;
import com.securestorage.ui.views.LoginView;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.stage.Stage;

/**
 * JavaFX Application entry point.
 *
 * Launch it the easy way:
 *   Windows  →  double-click run.bat
 *   macOS/Linux →  ./run.sh
 *
 * Or by hand, once built:
 *   mvn -q package
 *   java -jar target/securevault-3.0.0.jar
 *
 * Default credentials: admin / Admin@Secure123!
 */
public class SecureStorageApp extends Application {

    private Stage primaryStage;

    @Override
    public void init() {
        // Register Bouncy Castle before any UI exists, so the Encryption Lab
        // already knows whether the post-quantum algorithms are usable.
        PqcEngine.init();
    }

    @Override
    public void start(Stage stage) {
        this.primaryStage = stage;
        stage.setTitle("SecureVault — Secure File Storage System");
        stage.setMinWidth(1000);
        stage.setMinHeight(680);

        try {
            AppState.get().init();
        } catch (Exception e) {
            // v2 printed the stack trace and carried on into a login screen
            // backed by null services, which then failed in a confusing place.
            // Fail loudly and early instead.
            e.printStackTrace();
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("SecureVault could not start");
            alert.setHeaderText("Failed to initialise storage services");
            alert.setContentText(e.getMessage() + "\n\nData directory:\n" + AppState.BASE_DIR);
            alert.getDialogPane().setMinWidth(520);
            alert.showAndWait();
            Platform.exit();
            return;
        }

        showLogin();
        stage.show();
    }

    private void showLogin() {
        LoginView loginView = new LoginView(user -> showDashboard());
        Scene scene = new Scene(loginView, 1100, 720);
        primaryStage.setScene(scene);
    }

    private void showDashboard() {
        DashboardView dashboard = new DashboardView(() -> {
            AppState.get().clearSession();
            showLogin();
            primaryStage.setWidth(1100);
            primaryStage.setHeight(720);
        });
        Scene scene = new Scene(dashboard, 1280, 820);
        primaryStage.setScene(scene);
        primaryStage.setWidth(1280);
        primaryStage.setHeight(820);
        primaryStage.centerOnScreen();
    }

    @Override
    public void stop() {
        AppState.get().clearSession();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
