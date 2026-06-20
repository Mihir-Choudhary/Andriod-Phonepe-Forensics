"""
PhonePe Android Forensics — Case orchestrator
=============================================
``AndroidCase`` implements the ``Case`` object interface that ``webapp.py`` /
``case_manager.py`` depend on, by SUBCLASSING ``phonepe_forensics.case.Case`` and
inheriting its platform-agnostic derived views:

    timeline() · social_graph() · findings() · corroboration() ·
    lookup_counterparty() · dashboard() · export_all()

…all of which operate purely over ``self.data`` (the normalized contract). We override only
the Android-specific pieces:

    __init__              → AndroidCasePaths (the com.phonepe.app data layout)
    EXTRACTORS            → the Android extractor functions
    run_full_extraction   → run the Android extractors
    validate              → Android layout validation

``dashboard()`` is inherited unchanged: it already degrades gracefully when ``self.data['_v2']``
is absent (returns ``{"available": False}``). ``_tag_chat_self_direction`` is normalized-data
logic and is reused as-is once chat extraction is added.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List

from phonepe_forensics.case import Case
from phonepe_forensics.correlator import build_unified_timeline, detect_suspicious_signals

from . import extractors_android as aex
from .core_android import AndroidCasePaths

_SMS_AMOUNT_RX = re.compile(r"(?:rs\.?|inr|₹)\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)", re.I)
_SMS_FIN_RX = re.compile(r"debit|credit|sent|received|paid|withdraw|spent|txn|transaction|a/c|upi", re.I)


class AndroidCase(Case):
    """In-memory container for one PhonePe Android acquisition."""

    EXTRACTORS = [
        ("transactions", aex.extract_transactions),
        ("identity", aex.extract_identity),
        ("contacts", aex.extract_contacts),
        ("chat", aex.extract_chat),
        ("payment_infra", aex.extract_payment_infra),
        ("notifications", aex.extract_notifications),
        ("analytics", aex.extract_analytics),
        ("financial", aex.extract_financial),
        ("travel", aex.extract_travel),
        ("config_state", aex.extract_config_state),
        ("recommendations", aex.extract_recommendations),
        ("search", aex.extract_search),
        ("webkit", aex.extract_webkit),
        ("media", aex.extract_media),
        ("audit", aex.extract_audit),
        ("ledger", aex.extract_ledger),      # bill-splitting / shared expenses ("Split")
        ("sms", aex.extract_sms),            # Android-exclusive
        ("miniapps", aex.extract_miniapps),  # Android-exclusive (Nirvana RN services)
        # --- full-coverage layer: "parse everything, nothing skipped" ---
        ("files", aex.extract_files),                 # all files/ + DataStore protobuf + JSON
        ("shared_prefs", aex.extract_shared_prefs),   # all 176 shared_prefs/*.xml
        ("raw_tables", aex.extract_raw_tables),       # every row of every readable SQLite table
        ("encrypted_dbs", aex.extract_encrypted_dbs), # explicit record of unreadable encrypted DBs
    ]

    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.paths = AndroidCasePaths(self.root)
        self.data: Dict[str, Any] = {
            "_meta": {
                "platform": "android",
                "case_root": self.root,
                "loaded_at": int(time.time() * 1000),
                "containers": self.paths.summary(),
            },
        }
        self._extracted = False
        self._timeline = None
        self._social_graph = None
        self._findings = None

    def validate(self) -> Dict[str, Any]:
        ok = self.paths.is_valid()
        issues: List[str] = []
        if not self.paths.app_dir:
            issues.append(f"PhonePe app data dir (com.phonepe.app) not found under {self.root}")
        elif not self.paths.databases_dir:
            issues.append("databases/ directory not found in the app data dir")
        elif not self.paths.db("phonepe_core"):
            issues.append("phonepe_core database not found — this may not be a PhonePe Android extraction")
        if not self.paths.shared_prefs_dir:
            issues.append("shared_prefs/ missing — identity/token enrichment will be limited")
        return {"valid": ok, "issues": issues, "summary": self.paths.summary()}

    def run_full_extraction(self, on_progress=None) -> Dict[str, Any]:
        for i, (name, fn) in enumerate(self.EXTRACTORS, start=1):
            if on_progress:
                try:
                    on_progress(name, i, len(self.EXTRACTORS))
                except Exception:
                    pass
            try:
                self.data[name] = fn(self.paths)
            except Exception as exc:
                self.data[name] = {"error": str(exc)}
        try:
            self.data["database_inventory"] = aex.database_overview(self.paths)
        except Exception as exc:
            self.data["database_inventory"] = [{"error": str(exc)}]

        # NOTE: chat direction/is_self/other_party are set directly in extract_chat using
        # per-topic ownMemberId (more reliable than name-matching), so we deliberately
        # do NOT call _tag_chat_self_direction here.
        # NOTE: no extra enrichment pass — the Android extractors are self-contained.

        self._findings = detect_suspicious_signals(self.data) + self._android_findings()
        self.data["findings"] = self._findings
        self._extracted = True
        return self.data

    # ---- Android-specific analysis (kept in this package, not the shared correlator) ----

    def timeline(self, limit: int = 5000) -> List[Dict[str, Any]]:
        """Unified timeline = shared correlator events + Android-only sources (SMS, ledger)."""
        if self._timeline is None:
            events = build_unified_timeline(self.data, limit=999_999)
            events.extend(self._android_timeline_events())
            events.sort(key=lambda e: e["when_ms"], reverse=True)
            self._timeline = events
        return self._timeline[:limit]

    def _android_timeline_events(self) -> List[Dict[str, Any]]:
        ev: List[Dict[str, Any]] = []
        for m in self.data.get("sms", {}).get("messages", []):
            ts = m.get("received_at")
            if ts:
                ev.append({"when_ms": ts["epoch_ms"], "when_iso": ts["iso"], "source": "SMS",
                           "kind": "SMS", "title": f"SMS from {m.get('address')}",
                           "detail": {"body": (m.get("body") or "")[:160]}, "link_id": None})
        for e in self.data.get("ledger", {}).get("expenses", []):
            ts = e.get("created_at")
            if ts:
                ev.append({"when_ms": ts["epoch_ms"], "when_iso": ts["iso"], "source": "Ledger",
                           "kind": "SPLIT_" + (e.get("type") or "EXPENSE"),
                           "title": f"Split: {e.get('payer') or '?'} paid ₹{e.get('amount_inr')}",
                           "detail": {"settlement_txn": e.get("settlement_txn_id")},
                           "link_id": e.get("settlement_txn_id"), "amount_inr": e.get("amount_inr")})
        return ev

    def sms_corroboration(self) -> Dict[str, Any]:
        """Cross-check the transaction ledger against ingested bank SMS (amount + time window).
        Surfaces: txns confirmed by an independent SMS, txns with no SMS (possible deletion),
        and financial SMS with no matching txn (activity outside the app)."""
        WINDOW_MS = 30 * 60 * 1000  # ±30 min
        txns = [t for t in self.data.get("transactions", {}).get("transactions", [])
                if t.get("amount_inr") is not None and t.get("created_at")]
        sms = []
        for m in self.data.get("sms", {}).get("messages", []):
            body = m.get("body") or ""
            am = _SMS_AMOUNT_RX.search(body)
            if not am or not _SMS_FIN_RX.search(body) or not m.get("received_at"):
                continue
            try:
                amt = float(am.group(1).replace(",", ""))
            except ValueError:
                continue
            sms.append({"amt": amt, "ms": m["received_at"]["epoch_ms"],
                        "sender": m.get("address"), "body": body})
        matches, used_sms = [], set()
        confirmed = 0
        for t in txns:
            tms = t["created_at"]["epoch_ms"]; tamt = t["amount_inr"]
            hit = None
            for i, s in enumerate(sms):
                if i in used_sms:
                    continue
                if abs(s["amt"] - tamt) < 1.0 and abs(s["ms"] - tms) <= WINDOW_MS:
                    hit = (i, s); break
            if hit:
                used_sms.add(hit[0]); confirmed += 1
                matches.append({"txn_time": t["created_at"]["iso"], "amount_inr": tamt,
                                "direction": t.get("direction"), "counterparty": t.get("counterparty"),
                                "sms_sender": hit[1]["sender"], "sms_snippet": hit[1]["body"][:120]})
        return {
            "confirmed_count": confirmed,
            "uncorroborated_count": len(txns) - confirmed,
            "sms_only_count": len(sms) - len(used_sms),
            "financial_sms_count": len(sms),
            "matches": matches,
        }

    def _android_findings(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        dev = self.data.get("identity", {}).get("device_identifiers", {})
        if dev.get("is_rooted") is True:
            out.append({"severity": "high", "category": "rooted_device",
                        "title": "Device is rooted", "detail": {"model": dev.get("device_model")}})
        enc = self.data.get("encrypted_dbs", {}).get("encrypted", [])
        if enc:
            out.append({"severity": "info", "category": "encrypted_databases",
                        "title": f"{len(enc)} encrypted DB(s) present (not decryptable offline)",
                        "detail": {"names": [e["name"] for e in enc]}})
        try:
            corr = self.sms_corroboration()
            if corr["uncorroborated_count"] and corr["financial_sms_count"]:
                out.append({"severity": "info", "category": "sms_corroboration",
                            "title": f"{corr['confirmed_count']} txns confirmed by bank SMS; "
                                     f"{corr['sms_only_count']} financial SMS without a matching txn",
                            "detail": {k: corr[k] for k in ("confirmed_count", "uncorroborated_count", "sms_only_count")}})
        except Exception:
            pass
        return out
