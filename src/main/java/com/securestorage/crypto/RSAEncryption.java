package com.securestorage.crypto;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.*;

/**
 * RSA-2048 with OAEP Padding — for AES Key Wrapping
 *
 * Role in hybrid encryption: encrypts the AES session key (32 bytes),
 * not the file data. This solves the key exchange problem:
 *  - AES is fast but requires a shared secret
 *  - RSA is slow but enables asymmetric key exchange
 *
 * Why OAEP padding over PKCS#1 v1.5?
 * ┌───────────────────────────────────────────────────────────────────┐
 * │ Property          │ PKCS#1 v1.5         │ OAEP (chosen)           │
 * ├───────────────────────────────────────────────────────────────────┤
 * │ Security model    │ IND-CPA only        │ IND-CCA2 (stronger)     │
 * │ Bleichenbacher   │ Vulnerable (1998)   │ Not applicable          │
 * │ Hash function    │ None                │ SHA-256 (collision-safe) │
 * │ Modern standard  │ Legacy              │ NIST SP 800-131A rev2   │
 * └───────────────────────────────────────────────────────────────────┘
 *
 * RSA-2048 can encrypt at most 190 bytes with OAEP-SHA256.
 * Our AES-256 key is 32 bytes — well within that limit.
 *
 * Key formats used:
 *  - Public key:  X.509 SubjectPublicKeyInfo (standard serialization)
 *  - Private key: PKCS#8 PrivateKeyInfo
 */
public class RSAEncryption {

    private static final String ALGORITHM      = "RSA";
    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final int    KEY_SIZE_BITS  = 2048;

    // ══════════════════════ Key Generation ═══════════════════════

    /**
     * Generates a new RSA-2048 key pair.
     *
     * Key generation is expensive (~100–500ms on first call due to prime search).
     * Keys should be generated once and persisted via KeyManager.
     *
     * @return RSA-2048 KeyPair (public + private key)
     * @throws NoSuchAlgorithmException if RSA is not available
     */
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
        kpg.initialize(KEY_SIZE_BITS, new SecureRandom());
        return kpg.generateKeyPair();
    }

    // ════════════════ Encrypt / Decrypt AES Key ══════════════════

    /**
     * Encrypts data (the AES session key) using an RSA public key.
     *
     * This is called "key wrapping" — the AES key is wrapped inside
     * an RSA-encrypted envelope. Only the holder of the matching private
     * key can unwrap (decrypt) it.
     *
     * @param data      Data to encrypt (32-byte AES key)
     * @param publicKey RSA public key of the intended recipient
     * @return          RSA-encrypted ciphertext (256 bytes for RSA-2048)
     * @throws Exception on cipher failure
     */
    public byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * Decrypts RSA-wrapped data using the RSA private key.
     *
     * @param encryptedData 256-byte RSA ciphertext
     * @param privateKey    RSA private key
     * @return              Original plaintext (the AES key bytes)
     * @throws Exception on cipher failure or wrong key
     */
    public byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    // ══════════════════ Key Serialization ════════════════════════

    /**
     * Converts a PublicKey to bytes (X.509 SubjectPublicKeyInfo format).
     * Safe to store and transmit.
     */
    public byte[] publicKeyToBytes(PublicKey publicKey) {
        return publicKey.getEncoded();
    }

    /**
     * Converts a PrivateKey to bytes (PKCS#8 format).
     * MUST be stored securely (encrypted at rest in production).
     */
    public byte[] privateKeyToBytes(PrivateKey privateKey) {
        return privateKey.getEncoded();
    }

    /**
     * Reconstructs a PublicKey from stored X.509 bytes.
     */
    public PublicKey publicKeyFromBytes(byte[] bytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        return KeyFactory.getInstance(ALGORITHM).generatePublic(spec);
    }

    /**
     * Reconstructs a PrivateKey from stored PKCS#8 bytes.
     */
    public PrivateKey privateKeyFromBytes(byte[] bytes) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        return KeyFactory.getInstance(ALGORITHM).generatePrivate(spec);
    }
}
