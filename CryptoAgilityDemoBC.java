import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * CryptoAgilityDemoBC.java
 * ========================
 * The same three jobs as CryptoAgilityDemo.java, but the post-quantum
 * algorithms come from BouncyCastle 1.80+ instead of the JDK. Use this when
 * you are on JDK 17 or 21 and cannot upgrade to JDK 24+ yet.
 *
 *   [1] SIGN          ML-DSA-65
 *   [2] KEY EXCHANGE  ML-KEM-768
 *   [3] ENCRYPT       AES-256-GCM
 *
 * Migration path: on JDK 24+, remove the provider registration and the "BC"
 * arguments and the same JCA calls run on the native JDK provider
 * (see CryptoAgilityDemo.java).
 *
 * Compile and run (needs the BouncyCastle jar, e.g. bcprov-jdk18on-1.80.jar):
 *     javac -cp bcprov-jdk18on-1.80.jar CryptoAgilityDemoBC.java
 *     java  -cp .:bcprov-jdk18on-1.80.jar CryptoAgilityDemoBC     (macOS/Linux)
 *     java  -cp .;bcprov-jdk18on-1.80.jar CryptoAgilityDemoBC     (Windows)
 *
 * Educational demo - not production security software.
 */
public class CryptoAgilityDemoBC {

    // In a real project these would come from a config file, as in
    // CryptoAgilityDemo.java. Kept as constants here to keep the file short.
    static final String SIG_ALG = "ML-DSA-65";
    static final String KEM_ALG = "ML-KEM-768";

    private static final byte[] DOCUMENT =
        "Customer contract - must remain trustworthy for the full retention period."
        .getBytes(StandardCharsets.UTF_8);
    private static final byte[] MESSAGE =
        "Hello, quantum world!".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) throws Exception {
        // The one line specific to BouncyCastle. Remove on JDK 24+.
        Security.addProvider(new BouncyCastleProvider());
        Provider bc = Security.getProvider("BC");

        System.out.println(line('='));
        System.out.println("  Crypto-Agility Demo (BouncyCastle)      JDK: "
            + System.getProperty("java.specification.version"));
        System.out.println(line('='));
        System.out.println("  Provider : " + bc.getInfo());

        // ---- [1] SIGN -----------------------------------------------------
        KeyPair sigKp = KeyPairGenerator.getInstance(SIG_ALG, "BC").generateKeyPair();
        Signature signer = Signature.getInstance(SIG_ALG, "BC");
        signer.initSign(sigKp.getPrivate());
        signer.update(DOCUMENT);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(SIG_ALG, "BC");
        verifier.initVerify(sigKp.getPublic());
        verifier.update(DOCUMENT);
        boolean verified = verifier.verify(sig);

        System.out.printf("%n[1] SIGN             %s%n", SIG_ALG);
        System.out.printf("    Public key  : %,6d bytes%n", sigKp.getPublic().getEncoded().length);
        System.out.printf("    Signature   : %,6d bytes%n", sig.length);
        System.out.printf("    Verify      : %s%n", ok(verified));
        System.out.println("    Status      : POST-QUANTUM");

        // ---- [2] KEY EXCHANGE ---------------------------------------------
        // Recipient publishes a public key.
        KeyPair kemKp = KeyPairGenerator.getInstance(KEM_ALG, "BC").generateKeyPair();

        // Sender encapsulates: ciphertext goes over the wire, secret stays local.
        KeyGenerator kgSend = KeyGenerator.getInstance("ML-KEM", "BC");
        kgSend.init(new KEMGenerateSpec(kemKp.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) kgSend.generateKey();
        byte[] ciphertext = sent.getEncapsulation();

        // Recipient decapsulates with the private key.
        KeyGenerator kgRecv = KeyGenerator.getInstance("ML-KEM", "BC");
        kgRecv.init(new KEMExtractSpec(kemKp.getPrivate(), ciphertext, "AES"));
        SecretKeyWithEncapsulation received = (SecretKeyWithEncapsulation) kgRecv.generateKey();

        boolean match = Arrays.equals(sent.getEncoded(), received.getEncoded());
        SecretKey aesKey = new SecretKeySpec(received.getEncoded(), "AES");

        System.out.printf("%n[2] KEY EXCHANGE     %s%n", KEM_ALG);
        System.out.printf("    Public key  : %,6d bytes%n", kemKp.getPublic().getEncoded().length);
        System.out.printf("    Ciphertext  : %,6d bytes%n", ciphertext.length);
        System.out.printf("    Keys match  : %s   (fingerprint %s)%n", ok(match), fingerprint(aesKey.getEncoded()));
        System.out.printf("    Key length  : %d bits%n", aesKey.getEncoded().length * 8);
        System.out.println("    Status      : POST-QUANTUM");

        // ---- [3] ENCRYPT --------------------------------------------------
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
        enc.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
        byte[] ct = enc.doFinal(MESSAGE);
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding");
        dec.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
        boolean roundTrip = Arrays.equals(MESSAGE, dec.doFinal(ct));

        System.out.printf("%n[3] ENCRYPT          AES-%d-GCM (key from step 2)%n", aesKey.getEncoded().length * 8);
        System.out.printf("    Ciphertext  : %,6d bytes%n", ct.length);
        System.out.printf("    Decrypt     : %s%n", ok(roundTrip));

        System.out.println();
        System.out.println(line('-'));
        System.out.println("  Running post-quantum on JDK " + System.getProperty("java.specification.version") + " via BouncyCastle.");
        System.out.println("  On JDK 24+: drop BouncyCastle and use CryptoAgilityDemo.");
        System.out.println("  The business logic (sign / exchange / encrypt) does not change.");
        System.out.println(line('-'));
    }

    private static String ok(boolean b) { return b ? "[OK]" : "[FAIL]"; }

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
