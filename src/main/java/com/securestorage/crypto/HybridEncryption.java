package com.securestorage.crypto;

import javax.crypto.SecretKey;
import java.security.*;
import java.util.Arrays;

/**
 * Hybrid Encryption Engine: AES-256-GCM + RSA-2048-OAEP
 *
 * Combines the speed of symmetric encryption with the key-exchange
 * security of asymmetric cryptography.
 *
 * ════════════════════ ENCRYPTION WORKFLOW ════════════════════
 *
 *   Input File (plaintext)
 *        │
 *        ▼
 *   [1] Generate random AES-256 key  ◄── new key per file
 *        │
 *        ▼
 *   [2] AES-256-GCM encrypt file
 *        │                            ◄── fast: ~500 MB/s
 *        ▼
 *   [3] RSA-2048-OAEP wrap AES key   ◄── encrypts only 32 bytes
 *        │
 *        ▼
 *   EncryptedPackage { encryptedData, encryptedAesKey }
 *
 * ════════════════════ DECRYPTION WORKFLOW ════════════════════
 *
 *   EncryptedPackage
 *        │
 *        ▼
 *   [1] RSA-2048-OAEP unwrap AES key  ◄── requires private key
 *        │
 *        ▼
 *   [2] AES-256-GCM decrypt file      ◄── GCM verifies integrity
 *        │
 *        ▼
 *   Plaintext (with integrity guarantee)
 *
 * ════════════════ WHY HYBRID vs PURE RSA? ════════════════════
 *
 *   RSA-2048 max payload: ~190 bytes (OAEP-SHA256)
 *   A 1 MB file would require ~5,500 RSA blocks = extremely slow
 *   Hybrid solution: RSA encrypts only the 32-byte AES key (fast!)
 *
 * ════════════════════ RESEARCH METRICS ════════════════════════
 *
 *   Encryption time: measured per file size
 *   Decryption time: measured per file size
 *   Overhead %:      (encrypted_size - plaintext_size) / plaintext_size
 *   Correctness:     verified by round-trip test in benchmark
 */
public class HybridEncryption {

    private final AESEncryption aes;
    private final RSAEncryption rsa;

    public HybridEncryption() {
        this.aes = new AESEncryption();
        this.rsa = new RSAEncryption();
    }

    // ══════════════════════ Encrypt ══════════════════════════════

    /**
     * Encrypts a file using hybrid encryption.
     *
     * A fresh AES-256 key is generated for every file — this means
     * compromising one file's key does not compromise any other file.
     * (Perfect forward secrecy at the file level.)
     *
     * @param plaintext File content as bytes
     * @param publicKey RSA public key of the intended recipient
     * @return          EncryptedPackage containing both encrypted components
     * @throws Exception on cryptographic failure
     */
    public EncryptedPackage encrypt(byte[] plaintext, PublicKey publicKey) throws Exception {
        long start = System.nanoTime();

        // Step 1: Generate a fresh per-file AES-256 key
        SecretKey aesKey = aes.generateKey();

        // Step 2: Encrypt the file content with AES-256-GCM
        byte[] encryptedData = aes.encrypt(plaintext, aesKey);

        // Step 3: Wrap the AES key with RSA-2048-OAEP (only ~32 bytes encrypted here)
        byte[] encryptedAesKey = rsa.encrypt(aesKey.getEncoded(), publicKey);

        long encryptTimeMs = (System.nanoTime() - start) / 1_000_000L;

        return new EncryptedPackage(encryptedData, encryptedAesKey, encryptTimeMs);
    }

    // ══════════════════════ Decrypt ══════════════════════════════

    /**
     * Decrypts a hybrid EncryptedPackage.
     *
     * @param pkg        The encrypted file package
     * @param privateKey The RSA private key matching the key used during encryption
     * @return           Original plaintext bytes
     * @throws javax.crypto.AEADBadTagException if file was tampered with
     * @throws Exception on cryptographic failure or wrong private key
     */
    public byte[] decrypt(EncryptedPackage pkg, PrivateKey privateKey) throws Exception {
        // Step 1: Unwrap the AES key using the RSA private key
        byte[]    aesKeyBytes = rsa.decrypt(pkg.getEncryptedAesKey(), privateKey);
        SecretKey aesKey      = aes.keyFromBytes(aesKeyBytes);

        // Step 2: Decrypt file content and verify GCM auth tag
        return aes.decrypt(pkg.getEncryptedData(), aesKey);
    }

    // ══════════════════════ Benchmark ════════════════════════════

    /**
     * Benchmarks hybrid encryption across different file sizes.
     *
     * Research metrics collected:
     * - Encrypt time (ms) per size
     * - Decrypt time (ms) per size
     * - Encryption overhead % (size increase from IV + tag)
     * - Round-trip correctness (✓/✗)
     *
     * @param keyPair RSA key pair to use for the benchmark
     * @throws Exception on cryptographic failure
     */
    public void benchmark(KeyPair keyPair) throws Exception {
        int[] sizes = {
            1_024,          //   1 KB
            10_240,         //  10 KB
            102_400,        // 100 KB
            1_048_576       //   1 MB
        };

        System.out.println("  ┌──────────────────────────────────────────────────────────────┐");
        System.out.println("  │          HYBRID ENCRYPTION BENCHMARK (AES-256 + RSA-2048)    │");
        System.out.println("  ├──────────────┬──────────────┬──────────────┬────────┬────────┤");
        System.out.println("  │ File Size    │ Encrypt (ms) │ Decrypt (ms) │ OH %   │  OK?   │");
        System.out.println("  ├──────────────┼──────────────┼──────────────┼────────┼────────┤");

        SecureRandom random = new SecureRandom();
        for (int size : sizes) {
            byte[] original = new byte[size];
            random.nextBytes(original);

            // Encrypt
            long start   = System.nanoTime();
            EncryptedPackage pkg = encrypt(original, keyPair.getPublic());
            long encMs   = (System.nanoTime() - start) / 1_000_000L;

            // Decrypt
            start = System.nanoTime();
            byte[] decrypted = decrypt(pkg, keyPair.getPrivate());
            long decMs   = (System.nanoTime() - start) / 1_000_000L;

            // Metrics
            boolean match    = Arrays.equals(original, decrypted);
            double  overhead = 100.0 * (pkg.getTotalSizeBytes() - size) / size;
            String  label    = formatSize(size);

            System.out.printf("  │ %-12s │ %12d │ %12d │ %5.1f%% │  %s   │%n",
                label, encMs, decMs, overhead, match ? "✓" : "✗");
        }
        System.out.println("  └──────────────┴──────────────┴──────────────┴────────┴────────┘");
        System.out.println("  OH% = Encryption overhead (IV + auth tag + RSA key block)");
        System.out.println();
    }

    private String formatSize(int bytes) {
        if (bytes >= 1_048_576) return (bytes / 1_048_576) + " MB";
        if (bytes >= 1_024)     return (bytes / 1_024) + " KB";
        return bytes + " B";
    }

    /** Exposes the AES engine for direct use. */
    public AESEncryption getAes() { return aes; }

    /** Exposes the RSA engine for direct use. */
    public RSAEncryption getRsa() { return rsa; }
}
