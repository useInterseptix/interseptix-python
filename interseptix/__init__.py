"""
Interseptix Python SDK — local policy enforcement, no round-trip on tool calls.
"""

import os, re, json, threading, time, secrets
from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False

INTERSEPTIX_BASE_URL = os.environ.get("INTERSEPTIX_BASE_URL", "https://interseptix.com/v1")
_SDK_VERSION = "0.2.0"
_ALWAYS_BLOCKED = ("/_debug", "/internal/", "/admin/delete")

_PII = {
    "email":       re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "ssn":         re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "password":    re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+"),
}

# ── PCI DSS hard-strip patterns (card data MUST NEVER reach our servers) ──────
# These are stripped from payloads before _async_log sends anything.
_PCI_STRIP = [
    # Primary Account Numbers (PANs): 13-19 contiguous digits (Visa/MC/Amex/Discover)
    re.compile(r"\b(?:\d[ \-]?){13,19}\b"),
    # CVV/CVV2/CVC (3-4 digits following card-related keywords)
    re.compile(r"(?i)\b(cvv2?|cvc2?|security.?code)\s*[=:\"'\s]+\d{3,4}\b"),
    # Magnetic stripe / track data patterns
    re.compile(r"%B\d{13,19}\^"),
]

# ── HIPAA field-name detection (refuse to log PHI payloads) ───────────────────
_HIPAA_FIELDS = re.compile(
    r"(?i)\b(patient_id|patient_name|diagnosis|icd_?10|npi|phi|dob|date_of_birth"
    r"|mrn|medical_record|prescription|medication|health_plan|fhir|hl7)\b"
)

def _strip_pci(text: str) -> str:
    """Remove PAN/CVV patterns from text before it leaves the customer machine."""
    for pat in _PCI_STRIP:
        text = pat.sub("[PCI-REDACTED]", text)
    return text

def _has_hipaa(text: str) -> bool:
    """Return True if the payload contains HIPAA-sensitive field names."""
    return bool(_HIPAA_FIELDS.search(text))
_METHOD_SCOPE = {"GET":"read","HEAD":"read","POST":"write","PUT":"write","PATCH":"write","DELETE":"delete"}

@dataclass
class _Ctx:
    agent_id: Optional[str] = None
    scopes: list = field(default_factory=list)

_local = threading.local()
def _ctx():
    if not hasattr(_local,"c"): _local.c = _Ctx()
    return _local.c

def _op(val, op, ref):
    try:
        if op=="gt":  return float(val)>float(ref)
        if op=="lt":  return float(val)<float(ref)
        if op=="gte": return float(val)>=float(ref)
        if op=="lte": return float(val)<=float(ref)
        if op=="eq":  return str(val)==str(ref)
        if op=="neq": return str(val)!=str(ref)
        if op=="contains": return str(ref).lower() in str(val).lower()
        if op=="in":  return val in ref
    except: return False
    return False

def _extract(field, endpoint, method, payload_str):
    if field=="endpoint": return endpoint
    if field=="method":   return method
    try:
        d = json.loads(payload_str)
        return d.get(field)
    except: return None

def _evaluate_local(agent_id, scopes, method, endpoint, payload_str, rules, rate_count=0):
    for prefix in _ALWAYS_BLOCKED:
        if endpoint.startswith(prefix):
            return {"allowed":False,"outcome":"blocked","reason":f"permanently blocked: {endpoint}"}
    resource = endpoint.strip("/").split("/")[0] or "root"
    action   = _METHOD_SCOPE.get(method.upper(),"write")
    needed   = f"{action}:{resource}"
    if not (needed in scopes or f"*:{resource}" in scopes or "*:*" in scopes):
        return {"allowed":False,"outcome":"blocked","reason":f"missing scope {needed}"}
    redacted = []
    for rule in rules:
        r = rule.get("rules",{})
        for cond in r.get("deny_if",[]):
            val = _extract(cond["field"],endpoint,method,payload_str)
            if val is not None and _op(val,cond["op"],cond["value"]):
                return {"allowed":False,"outcome":"blocked","reason":f"policy '{rule.get('name')}': {cond['field']} {cond['op']} {cond['value']}"}
        for ep in r.get("deny_endpoints",[]):
            if endpoint.startswith(ep):
                return {"allowed":False,"outcome":"blocked","reason":f"blocked endpoint {ep}"}
        rl = r.get("rate_limit",{})
        if rl and rate_count >= rl.get("requests",9999):
            return {"allowed":False,"outcome":"blocked","reason":"rate limit exceeded"}
        for cond in r.get("require_approval_if",[]):
            val = _extract(cond["field"],endpoint,method,payload_str)
            if val is not None and _op(val,cond["op"],cond["value"]):
                return {"allowed":False,"outcome":"pending_approval","reason":f"approval needed: {cond['field']} {cond['op']} {cond['value']}","approval_id":f"appr_{secrets.token_hex(6)}"}
        if r.get("redact_pii"):
            for name,pat in _PII.items():
                if pat.search(payload_str): redacted.append(name)
    if not redacted:
        for name,pat in _PII.items():
            if pat.search(payload_str): redacted.append(name)
    return {"allowed":True,"outcome":"approved","reason":"ok","redacted_fields":redacted}

@dataclass
class Passport:
    agent_id: str
    name: str
    owner_email: str
    framework: str
    status: str
    effective_scopes: list
    tags: dict
    created_at: str

class Interseptix:
    """Interseptix SDK — two lines, local enforcement, async audit logs."""

    def __init__(self, api_key: str, base_url: str = INTERSEPTIX_BASE_URL, fail_open: bool = True):
        if not any(api_key.startswith(p) for p in ("isx_live_","isx_test_","krd_live_","krd_test_","aid_live_")):
            raise ValueError("Invalid API key format.")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.fail_open = fail_open
        self._org_id = self._tier = self._org_name = None
        self._features = []
        self._rules = []
        self._rules_lock = threading.RLock()
        self._ready = False
        self._client = httpx.Client(headers={"X-Api-Key":api_key,"X-SDK-Version":_SDK_VERSION},timeout=5.0) if _HAS_HTTPX else None
        self._load_config()
        self._install_interceptor()
        threading.Thread(target=self._refresh_loop, daemon=True).start()

    def _load_config(self):
        if not self._client:
            self._ready = self.fail_open; return
        try:
            r = self._client.post(f"{self.base_url}/auth/sdk-init", json={"sdk_version":_SDK_VERSION})
            if r.status_code == 200:
                d = r.json()
                self._org_id = d.get("org_id"); self._org_name = d.get("org_name")
                self._tier = d.get("tier","free"); self._features = d.get("features",[])
                with self._rules_lock: self._rules = d.get("rules",[])
                self._ready = True
            else:
                self._ready = self.fail_open
        except Exception as e:
            print(f"[Interseptix] Warning: {e}. Running {'open' if self.fail_open else 'closed'}.")
            self._ready = self.fail_open

    def _refresh_loop(self):
        while True:
            time.sleep(30)
            if not self._client: continue
            try:
                r = self._client.get(f"{self.base_url}/sdk/rules")
                if r.status_code == 200:
                    with self._rules_lock: self._rules = r.json().get("rules",[])
            except: pass

    def register(self, name, owner, framework="unknown", scopes=None, tags=None, parent_agent_id=None):
        if not self._client: raise RuntimeError("httpx required")
        payload = {"name":name,"owner_email":owner,"framework":framework,"scopes":scopes or [],"tags":tags or {}}
        if parent_agent_id: payload["parent_agent_id"] = parent_agent_id
        r = self._client.post(f"{self.base_url}/agents", json=payload)
        r.raise_for_status()
        d = r.json()
        p = Passport(agent_id=d["agent_id"],name=d["name"],owner_email=d["owner_email"],
                     framework=d["framework"],status=d["status"],effective_scopes=d["effective_scopes"],
                     tags=d["tags"],created_at=d["created_at"])
        c = _ctx(); c.agent_id = p.agent_id; c.scopes = p.effective_scopes
        return p

    def set_agent(self, agent_id, scopes=None):
        """Activate an agent for this thread.

        Base scopes are fetched automatically from your dashboard config.
        Pass `scopes` to grant *additional* runtime permissions on top of those.
        Effective scopes = dashboard scopes + any extras you pass here.
        """
        base_scopes = []
        if self._client:
            try:
                r = self._client.get(f"{self.base_url}/agents/{agent_id}", timeout=5.0)
                if r.status_code == 200:
                    base_scopes = r.json().get("effective_scopes", [])
            except Exception:
                pass
        extra = scopes or []
        merged = list(dict.fromkeys(base_scopes + extra))  # deduplicate, preserve order
        c = _ctx(); c.agent_id = agent_id; c.scopes = merged

    def _install_interceptor(self):
        if not _HAS_HTTPX: return
        sdk = self
        orig = httpx.Client.send
        def patched(client_self, request, *args, **kwargs):
            if sdk.base_url in str(request.url):
                return orig(client_self, request, *args, **kwargs)
            if not sdk._ready:
                if sdk.fail_open: return orig(client_self, request, *args, **kwargs)
                raise PermissionError("[Interseptix] SDK not ready.")
            c = _ctx()
            if not c.agent_id:
                return orig(client_self, request, *args, **kwargs)
            try: payload_str = request.content.decode("utf-8","ignore")
            except: payload_str = ""
            with sdk._rules_lock: rules = list(sdk._rules)
            decision = _evaluate_local(c.agent_id,c.scopes,request.method,str(request.url.path),payload_str,rules)
            sdk._async_log(c.agent_id, request, decision)
            if not decision["allowed"]:
                raise PermissionError(f"[Interseptix] {decision['outcome']}: {decision['reason']}")
            return orig(client_self, request, *args, **kwargs)
        httpx.Client.send = patched
        try:
            import requests
            orig_r = requests.Session.send
            def patched_r(s, req, **kw):
                if sdk.base_url in str(req.url): return orig_r(s,req,**kw)
                c = _ctx()
                if c.agent_id and not sdk._ready and not sdk.fail_open:
                    raise PermissionError("[Interseptix] SDK not ready.")
                return orig_r(s,req,**kw)
            requests.Session.send = patched_r
        except ImportError: pass

    def _async_log(self, agent_id, request, decision):
        def _send():
            if not self._client: return
            try:
                # ── PCI hard-strip: card data MUST NOT reach our servers ──────
                # Strip PANs and CVVs from the payload before it leaves this machine.
                try: raw = request.content.decode("utf-8", "ignore")
                except: raw = ""
                safe_payload = _strip_pci(raw)

                # ── HIPAA warning: log endpoint but not payload content ────────
                if _has_hipaa(safe_payload):
                    safe_payload = "[HIPAA-PAYLOAD-WITHHELD]"

                self._client.post(f"{self.base_url}/sdk/log", json={
                    "agent_id": agent_id,
                    "method":   request.method,
                    "endpoint": str(request.url.path),
                    "outcome":  decision.get("outcome", "approved"),
                    "reason":   decision.get("reason", ""),
                    "redacted": decision.get("redacted_fields", []),
                    "payload":  safe_payload,
                    "ts":       datetime.now(timezone.utc).isoformat(),
                }, timeout=2.0)
            except: pass
        threading.Thread(target=_send, daemon=True).start()

    def revoke(self, agent_id, revoked_by, reason, cascade=True):
        r = self._client.post(f"{self.base_url}/agents/{agent_id}/revoke",
            json={"revoked_by":revoked_by,"reason":reason,"cascade":cascade})
        r.raise_for_status(); return r.json()

    def heartbeat(self, agent_id):
        r = self._client.post(f"{self.base_url}/agents/{agent_id}/heartbeat")
        r.raise_for_status(); return r.json()

    def audit(self, agent_id=None, outcome=None, limit=50):
        params = {"limit":limit}
        if agent_id: params["agent_id"] = agent_id
        if outcome:  params["outcome"] = outcome
        r = self._client.get(f"{self.base_url}/audit", params=params)
        r.raise_for_status(); return r.json()

    # ── Token management (with caching) ───────────────────────────────

    def get_token(self, agent_id, scopes, ttl_seconds=900, task_id=None, refresh_buffer=60):
        """Issue a scoped action token, returning cached value if still valid."""
        if not hasattr(self, "_token_cache"):
            self._token_cache = {}
            self._token_lock = threading.RLock()
        cache_key = f"{agent_id}:{','.join(sorted(scopes))}"
        with self._token_lock:
            cached = self._token_cache.get(cache_key)
            if cached and cached["expires_at"] - time.time() > refresh_buffer:
                return cached["token"]
        payload = {"agent_id":agent_id,"scopes":scopes,"ttl_seconds":ttl_seconds}
        if task_id: payload["task_id"] = task_id
        r = self._client.post(f"{self.base_url}/tokens", json=payload)
        r.raise_for_status()
        d = r.json()
        try:
            exp_dt = datetime.fromisoformat(d["expires_at"].replace("Z","+00:00"))
            exp_ts = exp_dt.timestamp()
        except Exception:
            exp_ts = time.time() + ttl_seconds
        with self._token_lock:
            self._token_cache[cache_key] = {"token":d["token"],"expires_at":exp_ts}
        return d["token"]

    def intercept(self, agent_id, action_token, method, endpoint, payload=None, metadata=None):
        """Send an action to the server-side intercept endpoint."""
        r = self._client.post(f"{self.base_url}/actions/intercept", json={
            "agent_id":agent_id,"action_token":action_token,
            "method":method.upper(),"endpoint":endpoint,
            "payload":payload or {},"metadata":metadata or {},
        })
        r.raise_for_status(); return r.json()

    def guard(self, agent_id, scopes, method, endpoint, payload=None, metadata=None,
              ttl_seconds=900, raise_on_block=True):
        """Convenience: get_token + intercept in one call."""
        token = self.get_token(agent_id=agent_id, scopes=scopes, ttl_seconds=ttl_seconds)
        decision = self.intercept(agent_id=agent_id, action_token=token, method=method,
                                  endpoint=endpoint, payload=payload, metadata=metadata)
        if raise_on_block and not decision.get("allowed"):
            outcome = decision.get("outcome","blocked")
            message = decision.get("message","Action not allowed.")
            raise PermissionError(f"[interseptix:{outcome}] {message}")
        return decision

    # ── Roles ─────────────────────────────────────────────────────────

    def list_roles(self):
        r = self._client.get(f"{self.base_url}/roles")
        r.raise_for_status(); return r.json()

    def create_role(self, name, scopes, description=None):
        r = self._client.post(f"{self.base_url}/roles",
            json={"name":name,"scopes":scopes,"description":description})
        r.raise_for_status(); return r.json()

    def delete_role(self, role_id):
        r = self._client.delete(f"{self.base_url}/roles/{role_id}")
        r.raise_for_status(); return r.json()

    # ── Policies ──────────────────────────────────────────────────────

    def list_policies(self):
        r = self._client.get(f"{self.base_url}/policies")
        r.raise_for_status(); return r.json()

    def create_policy(self, name, rules, agent_ids=None, description=None):
        r = self._client.post(f"{self.base_url}/policies",
            json={"name":name,"rules":rules,"agent_ids":agent_ids or [],"description":description})
        r.raise_for_status(); return r.json()

    def toggle_policy(self, policy_id):
        r = self._client.patch(f"{self.base_url}/policies/{policy_id}")
        r.raise_for_status(); return r.json()

    def delete_policy(self, policy_id):
        r = self._client.delete(f"{self.base_url}/policies/{policy_id}")
        r.raise_for_status(); return r.json()

    # ── Approvals ─────────────────────────────────────────────────────

    def list_approvals(self, status="pending"):
        r = self._client.get(f"{self.base_url}/approvals", params={"status":status})
        r.raise_for_status(); return r.json()

    def approve(self, approval_id, resolved_by, note=None):
        r = self._client.post(f"{self.base_url}/approvals/{approval_id}/resolve",
            json={"decision":"approved","resolved_by":resolved_by,"note":note})
        r.raise_for_status(); return r.json()

    def deny(self, approval_id, resolved_by, note=None):
        r = self._client.post(f"{self.base_url}/approvals/{approval_id}/resolve",
            json={"decision":"denied","resolved_by":resolved_by,"note":note})
        r.raise_for_status(); return r.json()

    def __enter__(self): return self
    def __exit__(self, *args): pass
    def __repr__(self): return f"Interseptix(org={self._org_name!r}, tier={self._tier!r})"


InterseptixClient = Interseptix  # convenience alias
