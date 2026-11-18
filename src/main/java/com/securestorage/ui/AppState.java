package com.securestorage.ui;

import com.securestorage.auth.AuthManager;
import com.securestorage.auth.Permission;
import com.securestorage.auth.User;
import com.securestorage.logging.AuditLogger;
import com.securestorage.persistence.UserStore;
import com.securestorage.recovery.CheckpointManager;
import com.securestorage.recovery.TransactionLog;
import com.securestorage.research.ResearchExporter;
import com.securestorage.storage.SecureFileStorage;

import java.io.File;

/**
 * Application-wide singleton holding all initialised services.
 * Views obtain references from here rather than constructing their own.
 *
 * Directory layout under {user.home}/SecureStorageData :
 *   logs/           audit.log
 *   recovery/       write-ahead transaction log
 *   checkpoints/    checkpoint snapshots
 *   accounts/       users.dat            (hashes only, never passwords)
 *   storage/        data/*.enc, keys/*.pub, keys/*.pk8, index.dat
 *   research-data/  benchmark CSV + JSON + Markdown exports
 *   session.properties                   remembered login
 */
public class AppState {

    private static AppState instance;

    public static final String BASE_DIR = System.getProperty("user.home")
            + File.separator + "SecureStorageData";

    // Services
    private AuditLogger       auditLogger;
    private TransactionLog    transactionLog;
    private AuthManager       authManager;
    private SecureFileStorage fileStorage;
    private CheckpointManager checkpointManager;
    private ResearchExporter  researchExporter;

    // Session
    private String currentToken;
    private User   currentUser;

    private AppState() {}

    public static AppState get() {
        if (instance == null) instance = new AppState();
        return instance;
    }

    /** Initialises all backend services. Called once at app startup. */
    public void init() throws Exception {
        new File(BASE_DIR).mkdirs();
        auditLogger       = new AuditLogger(BASE_DIR + "/logs");
        transactionLog    = new TransactionLog(BASE_DIR + "/recovery");
        authManager       = new AuthManager(auditLogger, new UserStore(BASE_DIR + "/accounts"));
        fileStorage       = new SecureFileStorage(BASE_DIR + "/storage",
                                authManager, auditLogger, transactionLog);
        checkpointManager = new CheckpointManager(BASE_DIR + "/checkpoints");
        researchExporter  = new ResearchExporter(BASE_DIR);
    }

    // ── Getters ──────────────────────────────────────────────────
    public AuditLogger       getAuditLogger()      { return auditLogger; }
    public TransactionLog    getTransactionLog()   { return transactionLog; }
    public AuthManager       getAuthManager()      { return authManager; }
    public SecureFileStorage getFileStorage()      { return fileStorage; }
    public CheckpointManager getCheckpointManager(){ return checkpointManager; }
    public ResearchExporter  getResearchExporter() { return researchExporter; }

    // ── Session ──────────────────────────────────────────────────
    public String getCurrentToken() { return currentToken; }
    public User   getCurrentUser()  { return currentUser; }

    public void setSession(String token, User user) {
        this.currentToken = token;
        this.currentUser  = user;
    }

    /** Ends the session and wipes decrypted private keys from memory. */
    public void clearSession() {
        if (currentToken != null) authManager.logout(currentToken);
        if (fileStorage != null)  fileStorage.clearKeyCache();
        currentToken = null;
        currentUser  = null;
    }

    public boolean isLoggedIn() {
        return currentToken != null && currentUser != null;
    }

    /** Convenience for view-level permission checks. */
    public boolean can(Permission permission) {
        return currentUser != null && authManager.hasPermission(currentUser, permission);
    }
}
