import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.regex.*;

/**
 * CryptoAlgorithmScanner.java
 * ===========================
 * Scans Java source files for cryptographic patterns that are broken,
 * quantum-vulnerable, or weakened after quantum.
 *
 * This is step one of building a Cryptographic Bill of Materials (CBOM):
 * find where weak crypto lives before you plan how to migrate it.
 *
 * Findings are sorted into three urgency levels:
 *
 *   BROKEN TODAY       — already exploitable on classical hardware. Fix first.
 *   QUANTUM-VULNERABLE — safe today, broken by Shor's algorithm on a CRQC.
 *   WEAK AFTER QUANTUM — weakened (not broken) by Grover's algorithm.
 *
 * Usage:
 *     javac CryptoAlgorithmScanner.java
 *     java  CryptoAlgorithmScanner <directory>          # scan a directory tree
 *     java  CryptoAlgorithmScanner <file.java>          # scan a single file
 *     java  CryptoAlgorithmScanner .                    # scan current directory
 *
 * Caveat: this is plain text / regex matching. It finds patterns in source
 * code but cannot inspect compiled bytecode, third-party JARs, certificates,
 * TLS configuration, or dependency trees. Real CBOM tools go further.
 *
 * Educational demo — not a substitute for a professional security audit.
 */
public class CryptoAlgorithmScanner {

    // ── Pattern definitions ───────────────────────────────────────────────────
    // Each entry: { regex, description, category }
    // Categories: BROKEN TODAY | QUANTUM-VULNERABLE | WEAK AFTER QUANTUM

    private static final String[][] PATTERNS = {
        // ── BROKEN TODAY ─────────────────────────────────────────────────────
        { "\\bMD5\\b",
          "MD5 — broken, collision attacks demonstrated",
          "BROKEN TODAY" },
        { "\\bSHA[-_]?1\\b",
          "SHA-1 — broken, collision attacks demonstrated",
          "BROKEN TODAY" },
        { "[A-Z0-9]+-SHA(?![0-9])",
          "Cipher suite ending in -SHA uses SHA-1 — prefer -SHA256, -SHA384 or AEAD",
          "BROKEN TODAY" },
        { "\\bRC4\\b",
          "RC4 — broken, statistically biased output",
          "BROKEN TODAY" },
        { "(?<![A-Z0-9_])DES(?!3|_3|cription|tination|ktop)",
          "DES — 56-bit key, practically brute-forceable",
          "BROKEN TODAY" },
        { "\\b3DES\\b|Triple.?DES",
          "3DES — deprecated by NIST, migrate away",
          "BROKEN TODAY" },
        { "RSA.{0,10}1024",
          "RSA-1024 — key too short, retire immediately",
          "BROKEN TODAY" },
        { "ECDSA.{0,10}P-?192",
          "ECDSA P-192 — curve too small",
          "BROKEN TODAY" },

        // ── QUANTUM-VULNERABLE ────────────────────────────────────────────────
        { "getInstance\\s*\\(\\s*\"RSA\"",
          "RSA — replace with ML-DSA (signatures) or ML-KEM (key exchange)",
          "QUANTUM-VULNERABLE" },
        { "getInstance\\s*\\(\\s*\"EC(?:DH|DSA)?\"",
          "Elliptic-curve algorithm — replace with ML-KEM or ML-DSA",
          "QUANTUM-VULNERABLE" },
        { "getInstance\\s*\\(\\s*\"(?:DH|ECDH|X25519|X448)\"",
          "DH/ECDH key exchange — replace with ML-KEM",
          "QUANTUM-VULNERABLE" },

        // ── WEAK AFTER QUANTUM ────────────────────────────────────────────────
        { "(?:keyGen|KeyGenerator|init)\\s*[.(]\\s*128\\s*[),]",
          "AES-128 — use AES-256 (Grover's algorithm halves effective key strength)",
          "WEAK AFTER QUANTUM" },
    };

    // Compiled once at startup
    private static final List<PatternEntry> COMPILED = new ArrayList<>();

    static {
        for (String[] p : PATTERNS) {
            COMPILED.add(new PatternEntry(
                Pattern.compile(p[0], Pattern.CASE_INSENSITIVE),
                p[1], p[2]));
        }
    }

    // ── Entry point ───────────────────────────────────────────────────────────

    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.out.println("Usage: java CryptoAlgorithmScanner <path>");
            System.exit(1);
        }

        Path root = Paths.get(args[0]);
        List<Path> files = collectJavaFiles(root);

        if (files.isEmpty()) {
            System.out.println("No .java files found under: " + root);
            return;
        }

        System.out.println(line('='));
        System.out.println("  Crypto Algorithm Scanner    path: " + root.toAbsolutePath());
        System.out.println(line('='));
        System.out.printf("%n  Scanning %d file(s)...%n%n", files.size());

        Map<String, Integer> counts = new LinkedHashMap<>();
        counts.put("BROKEN TODAY", 0);
        counts.put("QUANTUM-VULNERABLE", 0);
        counts.put("WEAK AFTER QUANTUM", 0);
        int totalFindings = 0;

        for (Path file : files) {
            List<Finding> findings = scanFile(file);
            if (findings.isEmpty()) {
                System.out.println("  [OK] " + file);
            } else {
                System.out.println("  [!] " + file);
                for (Finding f : findings) {
                    System.out.printf("       line %3d  [%-18s]  %s%n",
                        f.lineNumber, f.category, f.description);
                    System.out.println("               " + f.lineText);
                }
                for (Finding f : findings) {
                    counts.merge(f.category, 1, Integer::sum);
                }
                totalFindings += findings.size();
            }
        }

        // ── Summary ───────────────────────────────────────────────────────────
        System.out.printf("%n  Total findings : %d%n", totalFindings);
        System.out.printf("  %-20s : %2d  — fix immediately%n",
            "BROKEN TODAY", counts.get("BROKEN TODAY"));
        System.out.printf("  %-20s : %2d  — migrate to ML-DSA / ML-KEM%n",
            "QUANTUM-VULNERABLE", counts.get("QUANTUM-VULNERABLE"));
        System.out.printf("  %-20s : %2d  — upgrade AES-128 to AES-256%n",
            "WEAK AFTER QUANTUM", counts.get("WEAK AFTER QUANTUM"));
        System.out.println();
        System.out.println("  Priority: BROKEN TODAY first, then QUANTUM-VULNERABLE");
        System.out.println("  (HNDL risk), then WEAK AFTER QUANTUM.");
        System.out.println();
        System.out.println("  Caveat: text matching is a starting point. Real CBOM");
        System.out.println("  tools also inspect bytecode, JARs, certificates,");
        System.out.println("  TLS config and dependency trees.");
        System.out.println(line('-'));
    }

    // ── Scanning ─────────────────────────────────────────────────────────────

    static List<Finding> scanFile(Path path) throws IOException {
        List<Finding> findings = new ArrayList<>();
        List<String> lines = Files.readAllLines(path);
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            for (PatternEntry pe : COMPILED) {
                if (pe.pattern.matcher(line).find()) {
                    findings.add(new Finding(i + 1, line.strip(), pe.description, pe.category));
                }
            }
        }
        return findings;
    }

    static List<Path> collectJavaFiles(Path root) throws IOException {
        List<Path> files = new ArrayList<>();
        if (Files.isRegularFile(root) && root.toString().endsWith(".java")) {
            files.add(root);
            return files;
        }
        Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path f, BasicFileAttributes a) {
                if (f.toString().endsWith(".java")) files.add(f);
                return FileVisitResult.CONTINUE;
            }
        });
        Collections.sort(files);
        return files;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static String line(char c) {
        StringBuilder sb = new StringBuilder(62);
        for (int i = 0; i < 62; i++) sb.append(c);
        return sb.toString();
    }

    // ── Data types ───────────────────────────────────────────────────────────

    record Finding(int lineNumber, String lineText, String description, String category) {}

    record PatternEntry(Pattern pattern, String description, String category) {}
}
