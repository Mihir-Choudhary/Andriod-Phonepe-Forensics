# PhonePe Android Forensics

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

## Limitations

- Three databases are **SQLCipher-encrypted** (incl. `AccountAggregatorDatabase`) and are
  recorded as present-but-not-decryptable — they need the device keystore key, which a
  file-system image does not contain.

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
