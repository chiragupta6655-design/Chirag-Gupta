# SecureVault 3.0.0

Role-based encrypted file storage with a built-in cryptographic benchmark lab,
covering both classical and NIST post-quantum primitives.

---

## Running it

**Windows** — double-click `run.bat`.
**macOS / Linux** — `chmod +x run.sh` once, then `./run.sh`.

The first run builds the JAR, which takes a minute or two while Maven downloads
JavaFX and Bouncy Castle. Every run after that starts straight from
`target/securevault-3.0.0.jar` with no build step.

After you change any source file, rebuild with `run.bat rebuild` or
`./run.sh rebuild`.

If the packaged JAR fails to start, both scripts fall back automatically to
`mvn javafx:run`, which loads JavaFX as proper modules.

Default credentials: `admin` / `Admin@Secure123!`

---

## What changed from v2

### 1. Private keys are no longer stored in the clear

v2 wrote each user's RSA private key to `{userId}.priv` as plain Base64. Anyone
who could read the storage folder could decrypt every file in the vault, which
made the rest of the encryption close to decorative against a local attacker.

v3 seals each private key with AES-256-GCM under a Key Encryption Key derived
from the owner's password:

```
password --PBKDF2-HMAC-SHA256(210,000 iterations, dedicated salt)--> KEK
KEK --AES-256-GCM--> encrypted PKCS#8 private key   ({userId}.pk8)
```

The KEK lives in memory for the length of a session and is wiped on sign-out.
The KEK salt is deliberately separate from the authentication salt, so the
stored password hash leaks nothing about the key that protects the private key.

What this does not defend against: an attacker who already has your password, or
who can read process memory while you are signed in. Closing those needs an HSM
or the OS keystore. That is noted as future work rather than claimed.

A side effect worth knowing about: an admin can now see that another user's file
exists and can delete it, but cannot read it. Per-user keys mean access control
is enforced by the cryptography, not only by the permission table. In v2 this
same attempt failed with a confusing RSA error; now it fails with an accurate
message.

### 2. BCrypt is a real authentication path

v2 implemented BCrypt but never called it — `AuthManager` used PBKDF2
exclusively and BCrypt appeared only inside the benchmark. Describing it as an
authentication mechanism would have been inaccurate.

v3 makes the choice real. `PasswordHasher.hash(password, algorithm)` selects,
`verify()` identifies the algorithm from the stored string, and a hash produced
by a non-default algorithm is transparently upgraded on the next successful
login. A vault can hold PBKDF2 and BCrypt records side by side.

### 3. Bouncy Castle is actually used

v2 declared `bcprov-jdk18on` in the POM with zero references anywhere in the
source. It now carries ML-KEM, ML-DSA and SLH-DSA.

### 4. Users and files persist

v2 kept both the user map and the file index in memory only, re-seeding admin at
every start. Any account you registered vanished on exit, and the File Manager
came back empty after a restart while orphaned `.enc` files piled up. Both are
now stored durably, written atomically, and read back through an
`ObjectInputFilter` allow-list.

### 5. Role-based navigation

The sidebar is built from the signed-in user's role:

| Role | Pages |
|---|---|
| ADMIN | Overview, File Manager, Encryption Lab, User Manager, Attack Simulator, Audit Logs, Recovery |
| USER | File Manager, Recovery |
| AUDITOR | Overview, Audit Logs |

Hiding a button is presentation, not security. Every operation behind these
pages still goes through `AuthManager.requirePermission`, and if the two ever
disagree the permission check is the one that decides.

### 6. Saved login

The sign-in screen remembers your username, and optionally your password.

Saved passwords are encrypted with AES-256-GCM under a random device key in
`~/SecureStorageData/.device.key`. Be clear about what that buys: the key sits
on the same disk as the encrypted password, so anyone who can log into your
account can recover it. It keeps the password out of plain text in a config
file, a screen share or a backup. It is not protection against someone who
already has your machine. The checkbox says so too.

Authentication also moved off the UI thread. PBKDF2 at 310,000 iterations plus
the KEK derivation is around half a second of deliberate CPU work, which in v2
froze the window on every sign-in.

---

## The Encryption Lab

### Why it is split into four tracks

A single leaderboard ranking AES-256-GCM, RSA-2048, ML-KEM, ML-DSA and SLH-DSA
against each other would be meaningless — they do different jobs. ML-KEM
establishes a key. ML-DSA and SLH-DSA sign and encrypt nothing. AES encrypts
bulk data. A reviewer would flag that on the first read.

| Track | Compared |
|---|---|
| Bulk encryption | AES-256-GCM across file sizes |
| Key establishment | RSA-2048-OAEP vs ML-KEM-512 / 768 / 1024 |
| Digital signatures | RSA-2048, ECDSA-P256 vs ML-DSA-44 / 65 / 87, SLH-DSA-SHA2-128f / 128s |
| Password hashing | PBKDF2-SHA256 vs BCrypt |

AES has no post-quantum counterpart in the table because it does not need one.
Grover's algorithm gives at best a quadratic speed-up against a symmetric
cipher, so a 256-bit key keeps roughly 128 bits of security against a quantum
adversary — which is exactly why the design uses AES-256 and not AES-128.

Every track measures **time and size**, because the headline result for
post-quantum cryptography is usually about bytes rather than milliseconds.

### Controls

- **Iterations** — each measurement is repeated and the median reported, so one
  JIT-warm-up outlier does not become your result.
- **Sizes** — Quick (1 KB – 1 MB) or Full (1 KB – 50 MB).
- **Verdict tab** — a written comparison generated from the numbers actually
  measured, including what the data does *not* support.

### If the PQC rows say UNAVAILABLE

The header chip shows `PQC UNAVAILABLE` and the console prints the reason.
Almost always it means Bouncy Castle is older than 1.80, which is the first
release with the finalised FIPS 203/204/205 algorithms in the main `BC`
provider. Run `run.bat rebuild` to pick up the version pinned in `pom.xml`.

`PqcEngine` resolves the Bouncy Castle parameter specs reflectively rather than
importing them. Those classes moved packages and changed names several times on
the way from the draft Kyber and Dilithium names to the final FIPS ones, so
binding them at compile time means the project stops compiling the moment the
dependency version moves. As written, the project builds with the JDK alone and
degrades to a clear "unavailable" message at runtime instead.

---

## Research data

`⇩ EXPORT RESEARCH DATA` writes to `~/SecureStorageData/research-data/`:

```
research-data/
  run-2026-09-16_143022/
      symmetric-encryption.csv     one row per file size
      key-establishment.csv        RSA-2048-OAEP vs each ML-KEM parameter set
      digital-signature.csv        RSA, ECDSA, ML-DSA, SLH-DSA
      password-hashing.csv         PBKDF2 vs BCrypt
      environment.json             JVM, OS, CPU count, heap, provider versions
      summary.md                   tables plus the caveats that belong with them
  all-runs.csv                     every measurement from every run, appended
```

`environment.json` exists because timings from a JIT-compiled language on a
laptop are not reproducible unless the machine and JVM are stated, and a
reviewer will ask.

`all-runs.csv` exists because one run is one sample. Run the benchmark five or
six times across a session and you can report a median with a spread instead of
a single number that happened to land where it did.

### Before you write this up

1. These results characterise **this implementation on this machine**, not the
   algorithms in general. The JDK's RSA is native; Bouncy Castle's ML-KEM is
   Java. Some of any gap you measure is implementation maturity, not
   mathematics. Say so — it is stronger than having it pointed out for you.
2. Report medians across runs, not single measurements.
3. Compare within a track only.
4. SLH-DSA's numbers will look bad. That is the finding, not a bug: it trades
   speed and size for a security argument that rests on hash functions alone,
   with no lattice assumption.

---

## Data layout

```
~/SecureStorageData/
  logs/           audit.log
  recovery/       write-ahead transaction log
  checkpoints/    checkpoint snapshots
  accounts/       users.dat        (password hashes only, never passwords)
  storage/
      data/       *.enc            (AES-256-GCM ciphertext + RSA-wrapped key)
      keys/       *.pub  X.509 public keys
                  *.pk8  AES-256-GCM sealed PKCS#8 private keys
      index.dat   file metadata index
  research-data/  benchmark exports
  session.properties, .device.key  saved login
```

### Upgrading from a v2 data folder

v2 private keys were written unencrypted as `.priv` and cannot be read by v3.
If you have an existing `~/SecureStorageData` from v2, delete
`storage/keys/` and `storage/index.dat` — new sealed keys are generated on the
next upload. Files encrypted under the old keys are not recoverable after that,
so move anything you care about out first.

---

## Build details

| | |
|---|---|
| Java | 17 or newer |
| JavaFX | 17.0.11 (resolved by Maven, platform classifier automatic) |
| Bouncy Castle | 1.80 (`bcprov-jdk18on`, `bcutil-jdk18on`) |
| BCrypt | jbcrypt 0.4 |
| Packaging | maven-shade-plugin, entry point `com.securestorage.Launcher` |

`Launcher` does not extend `Application` on purpose. JavaFX refuses to start
when its main class extends `Application` but the runtime was loaded from the
classpath rather than as named modules, which is exactly what a shaded fat JAR
does. Routing through a plain class skips that check, and it is why `java -jar`
works here with no `--module-path`.

The shade config strips `META-INF/*.SF`, `*.DSA` and `*.RSA`. `bcprov` ships
signed, repackaging invalidates the signature, and a stale signature file makes
the JVM reject the JAR. The non-FIPS BC provider does not verify its own
signature, so this is safe here — it would **not** be safe with `bc-fips`.
