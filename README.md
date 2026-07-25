# PhonePe Android Forensics

## 🙏 Credits & Acknowledgements

This tool was **inspired by, and built on the foundation of, [Sujay Adkesar](https://github.com/sujayadkesar)'s
[PhonePe-Forensics](https://github.com/sujayadkesar/PhonePe-Forensics)** project. Sujay's repository was
used as the **reference** to code this Android tool and to **understand the PhonePe forensic architecture**
(the normalized data contract, correlator/timeline/social-graph engine, hunt console and report layer).
Full credit and thanks to Sujay Adkesar for the original work that made this Android port possible.

> 🔜 **Coming soon:** this Android tool will be **merged back into Sujay's repo** so there is a **single
> tool that handles both iOS and Android** — instead of two separate tools. You'll pick the platform on
> launch and the analyser loads the matching parser and layout.

---

A local, **read-only** DFIR web tool that parses a PhonePe **Android** acquisition
(`com.phonepe.app`) and presents transactions, chat, contacts, the split/bill ledger,
identity & device fingerprint, a unified timeline, social graph and suspicious-signal
findings — all in a browser, with full source provenance for every field.

This is the **standalone, fully-Android** build: it boots straight into the Android
workspace (no operating-system picker) and parses every case as an Android acquisition.

> ⚠️ **Handles real personal data.** A PhonePe acquisition contains a person's complete
> financial, social and identity history. Use only on evidence you are authorised to
> examine. The tool is strictly read-only, but **never commit acquisitions, generated
> output, or the case registry** — they are excluded by `.gitignore` for this reason.

### How "read-only" is enforced

The evidence directory is never written to, so it works on a read-only mount and stays
byte-identical to the manifest taken at seizure:

- Every database and its `-wal` / `-shm` / `-journal` sidecars are **SHA-256 hashed before
  parsing**. The manifest appears on the Audit page and in `chain_of_custody.json`.
- A database with **no WAL** is opened in place with `immutable=1`, which cannot create or
  modify a file. (SQLite's ordinary `mode=ro` cannot do this: it still needs to create a
  `-shm` next to the database, which fails on read-only media and mutates the folder when
  it succeeds.)
- A database **carrying a WAL** is copied with its sidecars to a scratch directory and
  recovered there, so WAL-resident records are included without touching the original. The
  connection is switched to `query_only` once the schema is read.
- If a scratch copy cannot be staged, the database is opened `immutable` in place and a
  warning is raised on the dashboard, the Audit page and the exported report saying that
  `-wal` content is **not** included.

**All timestamps are UTC**, stated explicitly: `iso` is ISO-8601 with a `+00:00` offset and
`display` is suffixed `UTC`. The timestamp embedded in a PhonePe transaction ID is reported
as raw wall-clock digits and labelled *unvalidated* — the issuing server's timezone is
undocumented, so it is not treated as independent corroboration.

---

## Quick start

```bash
pip install -r requirements.txt
python run.py 127.0.0.1:8754
```

Then open the printed URL, click **+ New Case**, point it at the extracted
`com.phonepe.app` folder, and **Process**.

## What you feed it

Point a case at the PhonePe package data directory from a full-filesystem / rooted
Android extraction (Cellebrite, MSAB XRY, ADB backup of a rooted device):

```
.../data/data/com.phonepe.app/          ← select THIS folder
├── databases/                          Room SQLite — phonepe_core holds transactions,
│                                        chat, contacts, ledger (~160 tables)
├── shared_prefs/                       XML key/value (tokens, device IDs, flags)
├── files/                              DataStore, crashlytics, cached blobs
└── app_webview/                        Chromium cookies / local storage
```

## What it surfaces

- **Transactions** — amount, direction, counterparty, instrument, UTR, merchant, search tokens.
- **Chat & groups (Burble)**, **Contacts (Sampark)** — names deep-link to the person's chat thread.
- **Split / Bill ledger** — shared expenses, per-member shares, net balances, settlement→txn links.
- **Identity** — registered name/VPAs, device fingerprint, persistent IDs, sessions, location hints.
- **SMS inference**, **mini-apps (Switch)**, **payment infrastructure**, notifications, analytics.
- **Unified timeline**, **social graph**, **suspicious-signal findings**, **PPQL hunting**.
- **Raw layer** — every table (browsable + CSV), all shared_prefs, files & DataStore, a SQL console.
- **Provenance page** — the source DB/table/column or JSON path behind every surfaced field.

### Masked → real recovery

Where PhonePe source-masks a counterparty (`******1478`), the tool recovers the real
identity by **exact** cross-table lookup (connection_id / member_id / last-10 phone / VPA)
against the user's own contacts, and labels **each** recovered name by origin —
*saved in PhonePe* vs *phonebook* — so you can see both. Matches are exact only and
ambiguous phones (mapping to more than one person) are left unresolved, never guessed.

The same rule governs the social graph: chat activity is attributed by **connection id**,
never by display name, so two different contacts who share a name keep their own threads and
their own message counts. A thread whose counterparty cannot be resolved to a connection is
counted against the thread and marked as such, rather than being attached to a guessed name.

Bank-SMS corroboration matches **exact paise**, within ±30 minutes, one-to-one, nearest in
time first — so a transaction cannot be credited to an SMS belonging to a different payment
of a similar amount, and the confirmed/uncorroborated counts do not depend on row order.

## Limitations

- Three databases are **SQLiteCrypt-encrypted** (`AccountAggregatorDatabase`, `mdb`, and a
  UUID-named DB — each carries a `SQLitecrypt.com` header) and are recorded as
  present-but-not-decryptable. The whole-DB AES key is not on disk: the encrypted passphrase
  lives in `shared_prefs/common-encrypted-shared-pref.xml` (AndroidX `EncryptedSharedPreferences`),
  which is wrapped by a Tink keyset, which is wrapped by an **Android Keystore** master key whose
  bytes live in the device **TEE/StrongBox** and never touch the file system. A static image
  therefore cannot decrypt them — that needs the device's secure hardware (e.g. a rooted live
  device or runtime key extraction).

## Architecture

- `phonepe_android/` — the Android parser: `core_android`, `extractors_android` (20+ modules),
  `case_android` (`AndroidCase`), `provenance_android`.
- `phonepe_forensics/` — the **platform-agnostic** engine the Android layer reuses:
  `case` (base), `core` helpers, `correlator` (timeline / social graph / signals), `reports`,
  the Flask `webapp`, templates and static assets.

## Provenance

Vendored from the upstream PhonePe Forensics tool
(`github.com/sujayadkesar/PhonePe-Forensics`) at commit `007473a`, then reduced to an
Android-only distribution. The Android parser and the shared engine were copied (not submoduled),
so fixes made upstream after that point must be re-applied here.

## License

See `LICENSE`.
