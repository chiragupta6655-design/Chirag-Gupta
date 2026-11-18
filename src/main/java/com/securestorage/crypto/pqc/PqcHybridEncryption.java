package com.securestorage.crypto.pqc;

import com.securestorage.crypto.AESEncryption;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Post-quantum hybrid encryption: ML-KEM (FIPS 203) + AES-256-GCM.
 *
 * This is the structural twin of {@link com.securestorage.crypto.HybridEncryption},
 * with the RSA key-wrapping step replaced by a lattice-based key encapsulation.
 * Keeping the two paths structurally identical is what makes the Encryption Lab
 * comparison meaningful — the only variable is the key-establishment primitive.
 *
 * ┌──────────────────────── CLASSICAL (v2) ────────────────────────┐
 * │  random AES-256 key ──▶ AES-256-GCM(file)                      │
 * │  AES key ──RSA-2048-OAEP(recipient public key)──▶ 256 B blob   │
 * └────────────────────────────────────────────────────────────────┘
 * ┌────────────────────── POST-QUANTUM (v3) ───────────────────────┐
 * │  ML-KEM.Encaps(recipient public key) ──▶ (shared secret, ct)   │
 * │  shared secret ──▶ AES-256-GCM(file)                           │
 * │  ct is stored alongside; 1088 B for ML-KEM-768                 │
 * └────────────────────────────────────────────────────────────────┘
 *
 * The important structural difference: RSA *transports* a key you chose,
 * whereas a KEM *derives* one you did not choose. There is no step where a
 * caller-supplied secret is encrypted under the public key, which is why KEMs
 * sidestep the padding-oracle family of attacks entirely.
 *
 * Trade-off to report in a paper: the ML-KEM ciphertext is roughly 4x larger
 * than an RSA-2048 wrapped key (1088 B vs 256 B for the level-3 parameter set),
 * so per-file overhead rises — and that penalty is fixed, so it matters for
 * many small files and is negligible for a few large ones.
 */
public class PqcHybridEncryption {

    private final AESEncryption aes = new AESEncryption();
    private final PqcEngine.Kem parameterSet;

    public PqcHybridEncryption() { this(PqcEngine.Kem.ML_KEM_768); }

    public PqcHybridEncryption(PqcEngine.Kem parameterSet) {
        this.parameterSet = parameterSet;
    }

    /** Generates a recipient key pair for this parameter set. */
    public KeyPair generateKeyPair() throws Exception {
        return PqcEngine.generateKemKeyPair(parameterSet);
    }

    public PqcEngine.Kem getParameterSet() { return parameterSet; }

    // ── Encrypt ──────────────────────────────────────────────────────

    public PqcPackage encrypt(byte[] plaintext, PublicKey recipientPublic) throws Exception {
        long start = System.nanoTime();

        PqcEngine.Encapsulation enc = PqcEngine.encapsulate(recipientPublic);
        SecretKey aesKey = aes.keyFromBytes(enc.sharedSecret());
        byte[] encryptedData = aes.encrypt(plaintext, aesKey);

        long ms = (System.nanoTime() - start) / 1_000_000L;
        return new PqcPackage(encryptedData, enc.ciphertext(), parameterSet.displayName, ms);
    }

    // ── Decrypt ──────────────────────────────────────────────────────

    public byte[] decrypt(PqcPackage pkg, PrivateKey recipientPrivate) throws Exception {
        byte[] sharedSecret = PqcEngine.decapsulate(recipientPrivate, pkg.getKemCiphertext());
        SecretKey aesKey    = aes.keyFromBytes(sharedSecret);
        return aes.decrypt(pkg.getEncryptedData(), aesKey);
    }

    // ── Container ────────────────────────────────────────────────────

    /** Immutable container for a PQC-encrypted file. Mirrors EncryptedPackage. */
    public static class PqcPackage implements Serializable {

        private static final long serialVersionUID = 1L;

        private final byte[] encryptedData;   // IV + AES-GCM ciphertext + tag
        private final byte[] kemCiphertext;   // ML-KEM encapsulation
        private final String parameterSet;
        private final long   encryptTimeMs;

        public PqcPackage(byte[] encryptedData, byte[] kemCiphertext,
                          String parameterSet, long encryptTimeMs) {
            if (encryptedData == null || kemCiphertext == null) {
                throw new IllegalArgumentException("Encrypted components cannot be null");
            }
            this.encryptedData = encryptedData.clone();
            this.kemCiphertext = kemCiphertext.clone();
            this.parameterSet  = parameterSet;
            this.encryptTimeMs = encryptTimeMs;
        }

        public byte[] getEncryptedData() { return encryptedData.clone(); }
        public byte[] getKemCiphertext() { return kemCiphertext.clone(); }
        public String getParameterSet()  { return parameterSet; }
        public long   getEncryptTimeMs() { return encryptTimeMs; }

        public int getTotalSizeBytes() { return encryptedData.length + kemCiphertext.length; }

        @Override
        public String toString() {
            return String.format("PqcPackage{%s, kemCt=%d B, data=%d B, encTime=%d ms}",
                parameterSet, kemCiphertext.length, encryptedData.length, encryptTimeMs);
        }
    }
}
