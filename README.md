# crypto-agility-pqc-java

> A Java demo showing crypto-agility in practice: swap RSA and X25519 for ML-DSA and ML-KEM with one config change, scan your codebase for weak algorithms, and see the real size cost of post-quantum migration.

Companion code for the blog post **"Algorithms Expire: How Crypto-Agility Prepares You for the Quantum Era"** — *[link to be added on publish]*.

---

## What this project shows

Most Java applications hardcode their cryptographic algorithm names directly in code. When those algorithms eventually need replacing — and history says they always do — that means finding and changing every place they appear. This project demonstrates a better approach: **the algorithm comes from a config file, not from the code**.

Run the same program twice with two different config files:

| | `crypto-classical.properties` | `crypto-pqc.properties` |
|---|---|---|
| Signing | SHA256withRSA (RSA-2048) | ML-DSA-65 (FIPS 204) |
| Key exchange | DHKEM (X25519) | ML-KEM-768 (FIPS 203) |
| Encryption | AES-256-GCM | AES-256-GCM |
| Application code changed? | — | **No** |

The program signs a document, agrees on a shared secret using a Key Encapsulation Mechanism (KEM), and encrypts a message with AES-256-GCM. Both configs pass every check. The only thing that changes is one properties file. That is **crypto-agility** in practice.

> **New to quantum computing?**
> Quantum computers can break the math behind RSA and Diffie-Hellman (the algorithms most HTTPS connections use today). Symmetric encryption like AES is not broken — it just needs a 256-bit key instead of 128-bit. NIST (the US standards body) has already standardized the replacements: ML-KEM for key exchange and ML-DSA for digital signatures. Java ships both natively from JDK 24.

---

## Files

| File | What it does |
|---|---|
| `CryptoAgilityDemo.java` | Main demo — signs a document, exchanges a key, encrypts a message. Algorithm chosen by config. |
| `crypto-classical.properties` | The "before" config: RSA-2048, X25519, AES-256. What most Java apps use today. |
| `crypto-pqc.properties` | The "after" config: ML-DSA-65, ML-KEM-768, AES-256. Post-quantum, same code. |
| `CryptoAgilityDemoBC.java` | Same three steps via BouncyCastle, for teams stuck on JDK 17 or 21. |
| `CryptoAlgorithmScanner.java` | Scans Java source files for weak or quantum-vulnerable algorithms. |

---

## JDK requirements

| What you want to run | JDK needed |
|---|---|
| Classical config (`crypto-classical.properties`) | JDK 21 or later |
| Post-quantum config (`crypto-pqc.properties`) | **JDK 24 or later** (ML-DSA: JEP 497, ML-KEM: JEP 496) |
| BouncyCastle demo (`CryptoAgilityDemoBC`) | JDK 17 or later + BouncyCastle 1.80+ |
| Scanner (`CryptoAlgorithmScanner`) | JDK 21 or later |

Tested on JDK 21 (classical mode) and JDK 25 (all modes).

---

## Getting started

### 1. Compile

```bash
javac CryptoAgilityDemo.java
javac CryptoAlgorithmScanner.java
```

---

### 2. Run — classical baseline (JDK 21+)

```bash
java CryptoAgilityDemo crypto-classical.properties
```

**Expected output:**

```
==============================================================
  Crypto-Agility Demo      config: crypto-classical.properties
==============================================================

[1] SIGN             SHA256withRSA
    Public key  :    294 bytes
    Signature   :    256 bytes
    Verify      : [OK]
    Status      : LEGACY - quantum-vulnerable (Shor's algorithm)

[2] KEY EXCHANGE     DHKEM (X25519)
    Public key  :     44 bytes
    Ciphertext  :     32 bytes
    Keys match  : [OK]
    Status      : LEGACY - quantum-vulnerable (Shor's algorithm)

[3] ENCRYPT          AES-256-GCM (key from step 2)
    Plaintext   :     21 bytes  ("Hello, quantum world!")
    Ciphertext  :     37 bytes  (includes 16-byte auth tag)
    Decrypt     : [OK]
    Status      : OK - AES-256 keeps a safe margin against Grover's algorithm

--------------------------------------------------------------
  This is the classical baseline. Now run again with
  crypto-pqc.properties: same code, different config.
--------------------------------------------------------------
```

**What this output means:**

- **[1] SIGN** — The program generated an RSA-2048 key pair, signed a sample document with the private key, and verified the signature with the public key. `[OK]` means the signature is valid. The public key is 294 bytes and the signature is 256 bytes. The status says *quantum-vulnerable* because Shor's algorithm on a future quantum computer could forge RSA signatures.

- **[2] KEY EXCHANGE** — The two sides (sender and recipient, simulated in the same program) agreed on a shared secret without ever sending the secret over the wire. The sender used the recipient's public key to *encapsulate* the secret — producing a 32-byte ciphertext that was "sent". The recipient used their private key to *decapsulate* it and recover the same secret. `Keys match: [OK]` confirms both sides derived identical keys. Status is again *quantum-vulnerable* for the same reason.

- **[3] ENCRYPT** — The shared secret from step 2 became the AES-256 key. The message "Hello, quantum world!" (21 bytes) was encrypted with AES-256-GCM, producing 37 bytes (21 bytes of data + 16 bytes of authentication tag). `Decrypt: [OK]` confirms the message decrypted correctly. AES-256 is marked *OK* because Grover's algorithm only halves its effective strength, and 256-bit keys have enough margin.

This is your **before** picture. All checks pass, but the signing and key exchange are quantum-vulnerable. Now compare with the post-quantum run below — the same three steps, same code, different config.

---

### 3. Run — post-quantum (JDK 24+)

```bash
java CryptoAgilityDemo crypto-pqc.properties
```

**Expected output:**

```
==============================================================
  Crypto-Agility Demo      config: crypto-pqc.properties
==============================================================

[1] SIGN             ML-DSA-65
    Public key  :  1,974 bytes   (6.7x vs RSA-2048)
    Signature   :  3,309 bytes   (12.9x vs RSA-2048)
    Verify      : [OK]
    Status      : POST-QUANTUM

[2] KEY EXCHANGE     ML-KEM-768
    Public key  :  1,206 bytes   (27.4x vs X25519)
    Ciphertext  :  1,088 bytes   (34.0x vs DHKEM)
    Keys match  : [OK]
    Status      : POST-QUANTUM

[3] ENCRYPT          AES-256-GCM (key from step 2)
    Ciphertext  :     37 bytes
    Decrypt     : [OK]
    Status      : OK - AES-256 keeps a safe margin against Grover's algorithm

--------------------------------------------------------------
  Application code: unchanged.
  Only the config changed (compare with crypto-classical.properties).
  Sizes grew: test load balancers, proxies and size limits before rollout.
--------------------------------------------------------------
```

**What this output means:**

- **[1] SIGN** — The same signing step, now using ML-DSA-65 (NIST FIPS 204) instead of RSA. ML-DSA is built on lattice mathematics, which Shor's algorithm cannot break. `[OK]` means the signature verified correctly. Notice the size: the public key grew from 294 bytes to 1,974 bytes (about 6.7 times), and the signature grew from 256 bytes to 3,309 bytes (about 13 times). The math is more complex, and the output reflects that.

- **[2] KEY EXCHANGE** — Now using ML-KEM-768 (NIST FIPS 203) instead of X25519. The same encapsulate/decapsulate flow — the secret was never sent — but `Keys match: [OK]` confirms both sides still derived the same key. The ciphertext grew from 32 bytes to 1,088 bytes (about 34 times). That is the ciphertext that travels over the network.

- **[3] ENCRYPT** — Identical to the classical run. The ciphertext is still 37 bytes. AES-256-GCM is not replaced — it is simply fed a different key, one derived from ML-KEM instead of X25519. **Symmetric encryption is not part of the quantum problem.** This is the key insight: only key exchange and signing need replacing.

- **The closing message** — *"Application code: unchanged."* The same compiled `.class` file produced both outputs. Only the properties file changed. This is crypto-agility working.

> **The fingerprint changes every run.** The key-exchange secret is random, so its fingerprint (a short hash used for display) will differ each time you run. That is normal and expected. What matters is that sender and recipient fingerprints match *within* a single run.

---

### 4. Run the BouncyCastle demo (JDK 17 or 21)

If you are not yet on JDK 24, you can still run post-quantum algorithms today using **BouncyCastle**, an open-source cryptography library. Download `bcprov-jdk18on-1.80.jar` from [Maven Central](https://central.sonatype.com/artifact/org.bouncycastle/bcprov-jdk18on).

```bash
javac -cp bcprov-jdk18on-1.80.jar CryptoAgilityDemoBC.java
java  -cp .:bcprov-jdk18on-1.80.jar CryptoAgilityDemoBC     # macOS / Linux
java  -cp .;bcprov-jdk18on-1.80.jar CryptoAgilityDemoBC     # Windows
```

This produces the same post-quantum results (3,309-byte ML-DSA signature, 1,088-byte ML-KEM-768 ciphertext) on JDK 17 or 21. When you later upgrade to JDK 24+, remove the BouncyCastle jar and use `CryptoAgilityDemo.java` instead. The business logic — sign, exchange, encrypt — does not change.

---

### 5. Run the scanner

Point the scanner at any Java source directory or file to find weak or vulnerable algorithm usage:

```bash
java CryptoAlgorithmScanner .                        # scan the whole project
java CryptoAlgorithmScanner src/main/java            # scan a Maven source tree
java CryptoAlgorithmScanner MyService.java           # scan a single file
```

Findings are sorted into three urgency levels so you know what to fix first:

| Category | What it means | Examples found |
|---|---|---|
| **BROKEN TODAY** | Already exploitable on ordinary computers. Fix immediately, no quantum computer needed. | MD5, SHA-1, RC4, DES, RSA-1024, cipher suites ending in `-SHA` |
| **QUANTUM-VULNERABLE** | Safe today, but broken once a large enough quantum computer exists. Migrate to post-quantum. | `getInstance("RSA")`, `getInstance("EC")`, `getInstance("DH")` |
| **WEAK AFTER QUANTUM** | Weakened but not broken — fixable by increasing the key size. | `keyGen.init(128)` — raise to 256 |

> **Note:** this is plain text matching. It finds patterns in source code but cannot inspect compiled bytecode, third-party JARs, certificates, or TLS configuration. Real CBOM (Cryptographic Bill of Materials) tools go further. If you point the scanner at itself it will flag its own pattern strings — that is expected, not a bug.

---

## Why the sizes matter

Post-quantum algorithms are not a drop-in replacement with identical sizes. The growth is real and was measured from actual program output on JDK 25:

| | Classical | Post-quantum | Growth |
|---|---|---|---|
| Signature | 256 B (RSA-2048) | 3,309 B (ML-DSA-65) | ~13x |
| Signing public key | 294 B | 1,974 B | ~6.7x |
| Key-exchange ciphertext | 32 B (X25519) | 1,088 B (ML-KEM-768) | ~34x |
| AES-256-GCM output | 37 B | 37 B | none |

These larger sizes travel over the network and affect bandwidth, TLS handshake sizes, CDN limits, proxy buffers and constrained devices. A well-documented real case: a CDN rejected a post-quantum TLS handshake because its 1.2 KB key share exceeded an internal limit — even though health checks were passing. Test through your actual network path before deploying.

---

## Real-world context — how Java got here

Java has built post-quantum support incrementally, with lower-level building blocks arriving before higher-level features:

| JDK | What arrived |
|---|---|
| 21 | KEM API — the standard Java plumbing for key encapsulation |
| 24 | ML-KEM (JEP 496) and ML-DSA (JEP 497) — the actual post-quantum algorithms |
| 25 | Key Derivation Function API finalized (JEP 510) |
| 26 | ML-DSA support in `jarsigner` for signing JARs |
| 27 | Hybrid post-quantum TLS 1.3 *(confirm against current release notes)* |

For many Java applications, protection against **Harvest Now, Decrypt Later** attacks — where an adversary records encrypted traffic today and decrypts it once a quantum computer exists — can arrive as a JDK upgrade rather than a code rewrite. That is only possible because Java's security API was built for algorithm agility from the start. This project demonstrates that design in miniature.
