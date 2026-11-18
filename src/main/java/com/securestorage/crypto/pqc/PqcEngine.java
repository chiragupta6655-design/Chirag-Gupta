package com.securestorage.crypto.pqc;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Post-quantum cryptography engine — NIST FIPS 203 / 204 / 205.
 *
 *   ML-KEM   (FIPS 203)  Module-Lattice-Based Key-Encapsulation Mechanism
 *   ML-DSA   (FIPS 204)  Module-Lattice-Based Digital Signature Algorithm
 *   SLH-DSA  (FIPS 205)  Stateless Hash-Based Digital Signature Algorithm
 *
 * ── Why this class uses reflection ──────────────────────────────────
 * Bouncy Castle moved these algorithms between packages and renamed their
 * parameter-spec classes several times on the way from the draft Kyber and
 * Dilithium names to the finalised FIPS names. Binding to those classes at
 * compile time means the project stops compiling the moment the BC version
 * changes underneath it — which is exactly the sort of breakage you do not
 * want the night before a submission deadline.
 *
 * Everything here therefore goes through the standard JCA interfaces
 * (KeyPairGenerator / KeyGenerator / Signature) and looks the BC-specific
 * parameter specs up by name at runtime, trying each known spelling in turn.
 * The project compiles with the JDK alone; Bouncy Castle is only needed on the
 * classpath at run time. If it is missing or too old, {@link #isAvailable()}
 * returns false and the Encryption Lab shows the PQC rows as unavailable
 * instead of crashing.
 *
 * ── Honest scoping note ─────────────────────────────────────────────
 * ML-KEM is a key-encapsulation mechanism, so it is the like-for-like
 * replacement for RSA key wrapping — not for AES. ML-DSA and SLH-DSA are
 * signature schemes and encrypt nothing at all. The Encryption Lab compares
 * them within their own categories for this reason; a table that puts
 * "AES-256-GCM" and "SLH-DSA" in the same throughput column would be
 * measuring two unrelated things.
 */
public final class PqcEngine {

    // ── Algorithm descriptors ────────────────────────────────────────

    /** A KEM parameter set. */
    public enum Kem {
        ML_KEM_512 ("ML-KEM-512",  "ml_kem_512",  1, 800,  1632, 768),
        ML_KEM_768 ("ML-KEM-768",  "ml_kem_768",  3, 1184, 2400, 1088),
        ML_KEM_1024("ML-KEM-1024", "ml_kem_1024", 5, 1568, 3168, 1568);

        public final String displayName, specField;
        public final int nistCategory, publicKeyBytes, privateKeyBytes, ciphertextBytes;

        Kem(String d, String f, int cat, int pk, int sk, int ct) {
            displayName = d; specField = f; nistCategory = cat;
            publicKeyBytes = pk; privateKeyBytes = sk; ciphertextBytes = ct;
        }
    }

    /** A signature parameter set. */
    public enum Sig {
        ML_DSA_44 ("ML-DSA-44",  "MLDSAParameterSpec",  "ml_dsa_44",  2, "FIPS 204"),
        ML_DSA_65 ("ML-DSA-65",  "MLDSAParameterSpec",  "ml_dsa_65",  3, "FIPS 204"),
        ML_DSA_87 ("ML-DSA-87",  "MLDSAParameterSpec",  "ml_dsa_87",  5, "FIPS 204"),
        SLH_DSA_SHA2_128F("SLH-DSA-SHA2-128f", "SLHDSAParameterSpec", "slh_dsa_sha2_128f", 1, "FIPS 205"),
        SLH_DSA_SHA2_128S("SLH-DSA-SHA2-128s", "SLHDSAParameterSpec", "slh_dsa_sha2_128s", 1, "FIPS 205"),
        SLH_DSA_SHA2_192F("SLH-DSA-SHA2-192f", "SLHDSAParameterSpec", "slh_dsa_sha2_192f", 3, "FIPS 205");

        public final String displayName, specClass, specField, standard;
        public final int nistCategory;

        Sig(String d, String c, String f, int cat, String std) {
            displayName = d; specClass = c; specField = f; nistCategory = cat; standard = std;
        }

        /** True for the hash-based family, which has very different size/speed behaviour. */
        public boolean isHashBased() { return specClass.startsWith("SLHDSA"); }

        /** JCA service names to try, in order. */
        String[] jcaNames() {
            return isHashBased()
                ? new String[]{"SLH-DSA", "SLHDSA"}
                : new String[]{"ML-DSA", "MLDSA"};
        }
    }

    /** Result of a key encapsulation: the shared secret plus the ciphertext that carries it. */
    public record Encapsulation(byte[] sharedSecret, byte[] ciphertext) {}

    // ── Provider bootstrap ───────────────────────────────────────────

    private static final String BC_PROVIDER   = "BC";
    private static final String BC_CLASS      = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    private static final String SPEC_PACKAGE  = "org.bouncycastle.jcajce.spec.";

    private static volatile Boolean available;
    private static volatile String  unavailableReason = "not yet probed";
    private static volatile String  providerVersion   = "unknown";

    private PqcEngine() {}

    /** Registers Bouncy Castle if present. Safe to call repeatedly. */
    public static synchronized void init() {
        if (available != null) return;
        try {
            if (Security.getProvider(BC_PROVIDER) == null) {
                Class<?> cls = Class.forName(BC_CLASS);
                Provider p   = (Provider) cls.getDeclaredConstructor().newInstance();
                Security.addProvider(p);
            }
            Provider p = Security.getProvider(BC_PROVIDER);
            providerVersion = (p == null) ? "unknown" : p.getVersionStr();

            // Probe: can we actually build an ML-KEM key pair generator?
            resolveKeyPairGenerator(new String[]{"ML-KEM", "MLKEM"});
            available = true;
        } catch (ClassNotFoundException e) {
            available = false;
            unavailableReason = "Bouncy Castle (bcprov) is not on the classpath.";
        } catch (Throwable t) {
            available = false;
            unavailableReason =
                "Bouncy Castle " + providerVersion + " does not expose the FIPS 203/204/205 " +
                "algorithms. Upgrade bcprov-jdk18on to 1.80 or newer. (" + t.getClass().getSimpleName() + ")";
        }
    }

    public static boolean isAvailable()      { init(); return Boolean.TRUE.equals(available); }
    public static String  unavailableReason(){ init(); return unavailableReason; }
    public static String  providerInfo()     { init(); return "BouncyCastle " + providerVersion; }

    // ── ML-KEM (FIPS 203) ────────────────────────────────────────────

    /** Generates an ML-KEM key pair for the given parameter set. */
    public static KeyPair generateKemKeyPair(Kem set) throws GeneralSecurityException {
        requireAvailable();
        KeyPairGenerator kpg = resolveKeyPairGenerator(new String[]{"ML-KEM", "MLKEM"});
        AlgorithmParameterSpec spec = lookupSpec("MLKEMParameterSpec", set.specField, set.displayName);
        try {
            if (spec != null) kpg.initialize(spec, new SecureRandom());
            return kpg.generateKeyPair();
        } catch (InvalidAlgorithmParameterException e) {
            throw new GeneralSecurityException(
                "ML-KEM parameter set " + set.displayName + " rejected by this provider", e);
        }
    }

    /**
     * Encapsulates a fresh 256-bit shared secret to the holder of {@code recipientPublic}.
     * The returned ciphertext is what gets stored or transmitted; the secret never travels.
     */
    public static Encapsulation encapsulate(PublicKey recipientPublic) throws GeneralSecurityException {
        requireAvailable();
        try {
            KeyGenerator kg = resolveKeyGenerator(new String[]{"ML-KEM", "MLKEM"});
            AlgorithmParameterSpec genSpec = newSpec(
                SPEC_PACKAGE + "KEMGenerateSpec",
                new Class<?>[]{PublicKey.class, String.class, int.class},
                new Object[]{recipientPublic, "AES", 256});
            kg.init(genSpec, new SecureRandom());
            SecretKey secret = kg.generateKey();
            byte[] encapsulation = (byte[]) invoke(secret, "getEncapsulation");
            return new Encapsulation(secret.getEncoded(), encapsulation);
        } catch (GeneralSecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new GeneralSecurityException("ML-KEM encapsulation failed", e);
        }
    }

    /** Recovers the shared secret from a ciphertext using the recipient's private key. */
    public static byte[] decapsulate(PrivateKey recipientPrivate, byte[] ciphertext)
            throws GeneralSecurityException {
        requireAvailable();
        try {
            KeyGenerator kg = resolveKeyGenerator(new String[]{"ML-KEM", "MLKEM"});
            AlgorithmParameterSpec extractSpec = newSpec(
                SPEC_PACKAGE + "KEMExtractSpec",
                new Class<?>[]{PrivateKey.class, byte[].class, String.class, int.class},
                new Object[]{recipientPrivate, ciphertext, "AES", 256});
            kg.init(extractSpec);
            return kg.generateKey().getEncoded();
        } catch (GeneralSecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new GeneralSecurityException("ML-KEM decapsulation failed", e);
        }
    }

    // ── ML-DSA / SLH-DSA (FIPS 204 / 205) ────────────────────────────

    public static KeyPair generateSigKeyPair(Sig set) throws GeneralSecurityException {
        requireAvailable();
        KeyPairGenerator kpg = resolveKeyPairGenerator(set.jcaNames());
        AlgorithmParameterSpec spec = lookupSpec(set.specClass, set.specField, set.displayName);
        try {
            if (spec != null) kpg.initialize(spec, new SecureRandom());
            return kpg.generateKeyPair();
        } catch (InvalidAlgorithmParameterException e) {
            throw new GeneralSecurityException(
                set.displayName + " rejected by this provider", e);
        }
    }

    public static byte[] sign(PrivateKey key, byte[] message, Sig set) throws GeneralSecurityException {
        requireAvailable();
        Signature s = resolveSignature(set.jcaNames());
        s.initSign(key);
        s.update(message);
        return s.sign();
    }

    public static boolean verify(PublicKey key, byte[] message, byte[] signature, Sig set)
            throws GeneralSecurityException {
        requireAvailable();
        Signature s = resolveSignature(set.jcaNames());
        s.initVerify(key);
        s.update(message);
        return s.verify(signature);
    }

    // ── Reflection plumbing ──────────────────────────────────────────

    private static void requireAvailable() throws GeneralSecurityException {
        if (!isAvailable()) throw new GeneralSecurityException(unavailableReason());
    }

    private static KeyPairGenerator resolveKeyPairGenerator(String[] names) throws GeneralSecurityException {
        GeneralSecurityException last = null;
        for (String n : names) {
            try { return KeyPairGenerator.getInstance(n, BC_PROVIDER); }
            catch (GeneralSecurityException e) { last = e; }
        }
        throw last != null ? last : new NoSuchAlgorithmException(String.join("/", names));
    }

    private static KeyGenerator resolveKeyGenerator(String[] names) throws GeneralSecurityException {
        GeneralSecurityException last = null;
        for (String n : names) {
            try { return KeyGenerator.getInstance(n, BC_PROVIDER); }
            catch (GeneralSecurityException e) { last = e; }
        }
        throw last != null ? last : new NoSuchAlgorithmException(String.join("/", names));
    }

    private static Signature resolveSignature(String[] names) throws GeneralSecurityException {
        GeneralSecurityException last = null;
        for (String n : names) {
            try { return Signature.getInstance(n, BC_PROVIDER); }
            catch (GeneralSecurityException e) { last = e; }
        }
        throw last != null ? last : new NoSuchAlgorithmException(String.join("/", names));
    }

    /**
     * Finds a BC parameter-spec constant. Tries the documented static field first,
     * then the {@code fromName(String)} factory, then gives up and returns null so
     * the caller can fall back to the provider's default parameter set.
     */
    private static AlgorithmParameterSpec lookupSpec(String simpleClassName,
                                                     String fieldName,
                                                     String canonicalName) {
        String fqcn = SPEC_PACKAGE + simpleClassName;
        try {
            Class<?> cls = Class.forName(fqcn);
            try {
                Field f = cls.getField(fieldName);
                Object v = f.get(null);
                if (v instanceof AlgorithmParameterSpec spec) return spec;
            } catch (NoSuchFieldException ignored) {
                // fall through to fromName()
            }
            try {
                Method from = cls.getMethod("fromName", String.class);
                Object v = from.invoke(null, canonicalName);
                if (v instanceof AlgorithmParameterSpec spec) return spec;
            } catch (ReflectiveOperationException ignored) {
                // fall through
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // class absent on this BC version
        }
        return null;
    }

    private static AlgorithmParameterSpec newSpec(String fqcn, Class<?>[] sig, Object[] args)
            throws ReflectiveOperationException {
        Class<?> cls = Class.forName(fqcn);
        Constructor<?> ctor = cls.getConstructor(sig);
        return (AlgorithmParameterSpec) ctor.newInstance(args);
    }

    private static Object invoke(Object target, String method) throws ReflectiveOperationException {
        Method m = target.getClass().getMethod(method);
        m.setAccessible(true);
        return m.invoke(target);
    }
}
