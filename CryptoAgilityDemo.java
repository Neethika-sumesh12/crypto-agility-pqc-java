import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * CryptoAgilityDemo.java
 * ======================
 * One program, three jobs, algorithms chosen by a config file:
 *
 *   [1] SIGN          prove who you are          RSA        -> ML-DSA
 *   [2] KEY EXCHANGE  agree on a shared secret   X25519     -> ML-KEM
 *   [3] ENCRYPT       protect the data           AES-256 (same in both runs)
 *
 * The application code below never names an algorithm. Switching from
 * classical to post-quantum means passing a different properties file.
 *
 * JDK requirements:
 *   - crypto-classical.properties ... JDK 21+ (KEM API arrived in JDK 21)
 *   - crypto-pqc.properties ......... JDK 24+ (ML-DSA: JEP 497, ML-KEM: JEP 496)
 *   On JDK 17/21 use CryptoAgilityDemoBC.java (BouncyCastle) for post-quantum.
 *
 * Compile (with the JDK you will run on):
 *     javac CryptoAgilityDemo.java
 *
 * Run:
 *     java CryptoAgilityDemo crypto-classical.properties
 *     java CryptoAgilityDemo crypto-pqc.properties
 *
 * Educational demo - not production security software.
 */
public class CryptoAgilityDemo {

    private static final byte[] DOCUMENT =
        "Customer contract - must remain trustworthy for the full retention period."
        .getBytes(StandardCharsets.UTF_8);

    private static final byte[] MESSAGE =
        "Hello, quantum world!".getBytes(StandardCharsets.UTF_8);

    // Measured result of one step, so sizes can be compared between configs.
    record SignResult(int publicKeyBytes, int signatureBytes, boolean verified) {}
    record KemResult(int publicKeyBytes, int ciphertextBytes, boolean keysMatch,
                     String fingerprint, SecretKey key) {}

    public static void main(String[] args) throws Exception {
        String configFile = args.length > 0 ? args[0] : "crypto-classical.properties";
        Properties cfg = loadConfig(configFile);

        String keyAlg    = cfg.getProperty("key.algorithm");
        int    keySize   = Integer.parseInt(cfg.getProperty("key.size", "0"));
        String sigAlg    = cfg.getProperty("signature.algorithm");
        String kemName   = cfg.getProperty("kem.name");
        String kemKeyAlg = cfg.getProperty("kem.key.algorithm");
        int    aesBits   = Integer.parseInt(cfg.getProperty("symmetric.key.bits", "256"));

        boolean sigPq = isPostQuantum(sigAlg);
        boolean kemPq = isPostQuantum(kemName);

        System.out.println(line('='));
        System.out.println("  Crypto-Agility Demo      config: " + configFile);
        System.out.println(line('='));

        // When running a post-quantum config, also measure the classical
        // baseline live, so the size ratios shown are real measurements.
        SignResult sigBase = null;
        KemResult  kemBase = null;
        if (sigPq || kemPq) {
            try {
                if (sigPq) sigBase = sign("RSA", 2048, "SHA256withRSA");
                if (kemPq) kemBase = exchange("X25519", "DHKEM", 32);
            } catch (Exception e) {
                System.out.println("  (classical baseline unavailable: " + e + ")");
            }
        }

        // ---- [1] SIGN -----------------------------------------------------
        SignResult s;
        try {
            s = sign(keyAlg, keySize, sigAlg);
        } catch (NoSuchAlgorithmException e) {
            System.out.printf("%n[!] %s is not available on JDK %s.%n", sigAlg,
                System.getProperty("java.specification.version"));
            System.out.println("    ML-DSA and ML-KEM need JDK 24+ (JEP 497 / JEP 496).");
            System.out.println("    On JDK 17/21 run CryptoAgilityDemoBC.java (BouncyCastle) instead.");
            return;
        }
        System.out.printf("%n[1] SIGN             %s%n", sigAlg);
        System.out.printf("    Public key  : %,6d bytes%s%n", s.publicKeyBytes(),
            ratio(s.publicKeyBytes(), sigBase == null ? 0 : sigBase.publicKeyBytes(), "RSA-2048"));
        System.out.printf("    Signature   : %,6d bytes%s%n", s.signatureBytes(),
            ratio(s.signatureBytes(), sigBase == null ? 0 : sigBase.signatureBytes(), "RSA-2048"));
        System.out.printf("    Verify      : %s%n", ok(s.verified()));
        System.out.printf("    Status      : %s%n", sigPq
            ? "POST-QUANTUM"
            : "LEGACY - quantum-vulnerable (Shor's algorithm)");

        // ---- [2] KEY EXCHANGE ---------------------------------------------
        KemResult k = exchange(kemKeyAlg, kemName, aesBits / 8);
        System.out.printf("%n[2] KEY EXCHANGE     %s%s%n", kemName,
            kemName.equals(kemKeyAlg) ? "" : " (" + kemKeyAlg + ")");
        System.out.printf("    Public key  : %,6d bytes%s%n", k.publicKeyBytes(),
            ratio(k.publicKeyBytes(), kemBase == null ? 0 : kemBase.publicKeyBytes(), "X25519"));
        System.out.printf("    Ciphertext  : %,6d bytes%s%n", k.ciphertextBytes(),
            ratio(k.ciphertextBytes(), kemBase == null ? 0 : kemBase.ciphertextBytes(), "DHKEM"));
        System.out.printf("    Keys match  : %s   (fingerprint %s)%n", ok(k.keysMatch()), k.fingerprint());
        System.out.printf("    Status      : %s%n", kemPq
            ? "POST-QUANTUM"
            : "LEGACY - quantum-vulnerable (Shor's algorithm)");

        // ---- [3] ENCRYPT --------------------------------------------------
        // The shared secret from step 2 becomes the AES key.
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
        enc.init(Cipher.ENCRYPT_MODE, k.key(), new GCMParameterSpec(128, iv));
        byte[] ct = enc.doFinal(MESSAGE);
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding");
        dec.init(Cipher.DECRYPT_MODE, k.key(), new GCMParameterSpec(128, iv));
        boolean roundTrip = Arrays.equals(MESSAGE, dec.doFinal(ct));

        System.out.printf("%n[3] ENCRYPT          AES-%d-GCM (key from step 2)%n", aesBits);
        System.out.printf("    Plaintext   : %,6d bytes  (\"%s\")%n", MESSAGE.length,
            new String(MESSAGE, StandardCharsets.UTF_8));
        System.out.printf("    Ciphertext  : %,6d bytes  (includes 16-byte auth tag)%n", ct.length);
        System.out.printf("    Decrypt     : %s%n", ok(roundTrip));
        System.out.printf("    Status      : %s%n", aesBits >= 256
            ? "OK - AES-256 keeps a safe margin against Grover's algorithm"
            : "[WARN] AES-" + aesBits + " is weakened by Grover's algorithm - use 256");

        // ---- Closing message ----------------------------------------------
        System.out.println();
        System.out.println(line('-'));
        if (sigPq || kemPq) {
            System.out.println("  Application code: unchanged.");
            System.out.println("  Only the config changed (compare with crypto-classical.properties).");
            System.out.println("  Sizes grew: test load balancers, proxies and size limits before rollout.");
        } else {
            System.out.println("  This is the classical baseline. Now run again with");
            System.out.println("  crypto-pqc.properties: same code, different config.");
        }
        System.out.println(line('-'));
    }

    // ---- The three building blocks. None of them names an algorithm. --------

    static SignResult sign(String keyAlg, int keySize, String sigAlg) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlg);
        if (keySize > 0) kpg.initialize(keySize);
        KeyPair kp = kpg.generateKeyPair();

        Signature signer = Signature.getInstance(sigAlg);
        signer.initSign(kp.getPrivate());
        signer.update(DOCUMENT);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(sigAlg);
        verifier.initVerify(kp.getPublic());
        verifier.update(DOCUMENT);
        boolean valid = verifier.verify(sig);

        return new SignResult(kp.getPublic().getEncoded().length, sig.length, valid);
    }

    static KemResult exchange(String keyAlg, String kemName, int keyBytes) throws Exception {
        // Recipient generates a key pair and publishes the public key.
        KeyPair recipient = KeyPairGenerator.getInstance(keyAlg).generateKeyPair();

        // Sender encapsulates: produces a ciphertext (sent over the wire) and
        // a shared secret (never sent).
        KEM kem = KEM.getInstance(kemName);
        KEM.Encapsulated e = kem.newEncapsulator(recipient.getPublic())
                                .encapsulate(0, keyBytes, "AES");

        // Recipient decapsulates the ciphertext with the private key.
        SecretKey recovered = kem.newDecapsulator(recipient.getPrivate())
                                 .decapsulate(e.encapsulation(), 0, keyBytes, "AES");

        boolean match = Arrays.equals(e.key().getEncoded(), recovered.getEncoded());
        // Rebuild as a plain AES key so it can be used by the cipher in step 3.
        SecretKey aesKey = new SecretKeySpec(recovered.getEncoded(), "AES");

        return new KemResult(recipient.getPublic().getEncoded().length,
                             e.encapsulation().length, match, fingerprint(aesKey.getEncoded()), aesKey);
    }

    // ---- Helpers ---------------------------------------------------------------

    private static boolean isPostQuantum(String alg) {
        return alg.startsWith("ML-") || alg.startsWith("SLH-") || alg.startsWith("HSS");
    }

    private static String ratio(int value, int baseline, String baselineName) {
        if (baseline <= 0) return "";
        return String.format("   (%.1fx vs %s)", (double) value / baseline, baselineName);
    }

    private static String ok(boolean b) { return b ? "[OK]" : "[FAIL]"; }

    private static Properties loadConfig(String path) throws IOException {
        Properties p = new Properties();
        try (FileInputStream in = new FileInputStream(path)) { p.load(in); }
        return p;
    }

    /** First 8 bytes of SHA-256 of the key. Never print the key itself. */
    private static String fingerprint(byte[] keyBytes) throws NoSuchAlgorithmException {
        byte[] h = MessageDigest.getInstance("SHA-256").digest(keyBytes);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02X", h[i]));
        }
        return sb.append("...").toString();
    }

    private static String line(char c) {
        StringBuilder sb = new StringBuilder(62);
        for (int i = 0; i < 62; i++) sb.append(c);
        return sb.toString();
    }
}
