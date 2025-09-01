from __future__ import annotations

import argparse, hashlib, json, os, sys, time, re, random
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Dict

import requests
from bs4 import BeautifulSoup
from langdetect import detect
from pydantic import BaseModel, Field, ValidationError
import re, itertools, urllib.parse as ul

from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

import threading, collections, time as _time

from google import genai as genai

_SILENCE_PAT = re.compile(r"^\s*(no\s+se\s+menciona|no\s+aplica|n/?a|not\s+mentioned|unspecified)\s*\.?$", re.I)

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
CHUNK_TOKENS = 2000
CHUNK_OVERLAP = 250
MAX_RETRIES_LLM = 5

def load_done_hashes(path: Path) -> set[str]:
    done = set()
    if not path.exists():
        return done
    with path.open(encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rec = json.loads(ln)
            except json.JSONDecodeError:
                continue
            h = rec.get("sha1")
            if not h and "url" in rec:
                h = hashlib.sha1(rec["url"].encode()).hexdigest()
            if h:
                done.add(h)
    return done

def link_hash(link) -> str:
    return hashlib.sha1(link.url.encode()).hexdigest()

def find_balanced_json(s: str) -> str:
    start = s.find("{")
    if start == -1:
        raise ValueError("No JSON object found")
    depth, in_str, esc = 0, False, False
    for i, ch in enumerate(s[start:], start):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return s[start:i+1]
    raise ValueError("Unbalanced JSON")

def gemini_json(model_name: str, prompt: str, schema: dict) -> dict:
    client = genai.Client(api_key=os.environ["GOOGLE_API_KEY"])
    rsp = client.models.generate_content(
        model=model_name,
        contents=[{"role":"user","parts":[{"text":prompt}]}],
        config={
            "temperature": 0,
            "top_p": 0,
            "response_mime_type": "application/json",
            "response_schema": schema,
        },
    )

    txt = getattr(rsp, "text", None)
    if not txt and getattr(rsp, "candidates", None):
        parts = rsp.candidates[0].content.parts
        if parts and hasattr(parts[0], "text"):
            txt = parts[0].text
    if not txt:
        raise RuntimeError("empty JSON from model")

    return json.loads(txt)

def schema_of(doc_type: str) -> dict:
    raw = DOC_MODEL[doc_type].model_json_schema()
    defs = raw.get("$defs", {})

    def resolve(node):
        if isinstance(node, dict):
           if "$ref" in node:
                ref = node["$ref"]
                if ref.startswith("#/$defs/"):
                    name = ref.split("/")[-1]
                    target = defs.get(name, {})
                    return resolve(target)
           unsupported = {"$defs", "$schema", "additionalProperties", "title", "description", "examples"}
           return {k: resolve(v) for k, v in node.items() if k not in unsupported}
        if isinstance(node, list):
            return [resolve(x) for x in node]
        return node

    flat = resolve(raw)

    return {
        "type": "object",
        "properties": {"details": flat},
        "required": ["details"]
    }

class Rights(BaseModel):
    access: Optional[bool] = None
    rectification: Optional[bool] = None
    erasure: Optional[bool] = None
    opposition: Optional[bool] = None
    portability: Optional[bool] = None
    restriction: Optional[bool] = None
    no_individual_decision: Optional[bool] = None

    def merge(self, other: "Rights") -> None:
        for field in self.__class__.model_fields:
            val_self = getattr(self, field)
            val_other = getattr(other, field)
            if val_other is True:
                setattr(self, field, True)
            elif val_self is None and val_other is False:
                setattr(self, field, False)

class CookieDuration(BaseModel):
    session: Optional[bool] = None
    persistent: Optional[bool] = None
    max_exp: Optional[str] = None

class PrivacyDetails(BaseModel):
    controller: Optional[str] = None
    dpo_contact: Optional[str] = None
    purposes: List[str] = Field(default_factory=list)
    legal_bases: List[str] = Field(default_factory=list)
    source_of_data: Optional[str] = None
    retention: Optional[str] = None
    recipients: List[str] = Field(default_factory=list)
    transfer_scope: Optional[str] = None
    rights: Rights = Rights()
    rights_general_statement: Optional[bool] = None
    automated_decisions: Optional[bool] = None

    def merge(self, o: "PrivacyDetails") -> None:
        if o.transfer_scope is None and self.transfer_scope is None:
            pass
        for k in ("purposes", "legal_bases", "recipients"):
            setattr(self, k, list(dict.fromkeys(getattr(self, k) + getattr(o, k))))
        for k in ("controller", "dpo_contact", "source_of_data", "retention"):
            if getattr(o, k) and not getattr(self, k):
                setattr(self, k, getattr(o, k))
        scope_rank = {None: 0, "NONE": 1, "INTRA_EU": 2, "INTERNATIONAL": 3}
        if scope_rank.get(o.transfer_scope, 0) > scope_rank.get(self.transfer_scope, 0):
            self.transfer_scope = o.transfer_scope
        self.rights.merge(o.rights)
        if o.rights_general_statement is True:
            self.rights_general_statement = True
        if o.automated_decisions is True or self.automated_decisions is None:
            self.automated_decisions = o.automated_decisions

class CookieDetails(BaseModel):
    ownership: Optional[str] = None
    third_parties: List[str] = Field(default_factory=list)
    types: List[str] = Field(default_factory=list)
    purpose: List[str] = Field(default_factory=list)
    duration: CookieDuration = CookieDuration()
    consent_mechanism: Optional[str] = None
    mgmt_instructions: Optional[bool] = None
    def merge(self, o: "CookieDetails") -> None:
        for k in ("third_parties", "types", "purpose"):
            setattr(self, k, list(dict.fromkeys(getattr(self, k) + getattr(o, k))))
        if self.ownership is None:
            self.ownership = o.ownership
        elif o.ownership == "MIXED" or (self.ownership == "FIRST" and o.ownership != "FIRST"):
            self.ownership = o.ownership
        self.duration.session = self.duration.session or o.duration.session
        self.duration.persistent = self.duration.persistent or o.duration.persistent
        if self.duration.max_exp is None and o.duration.max_exp:
            self.duration.max_exp = o.duration.max_exp
        if self.consent_mechanism is None and o.consent_mechanism:
            self.consent_mechanism = o.consent_mechanism
        if o.mgmt_instructions is True:
            self.mgmt_instructions = True

class LegalNoticeDetails(BaseModel):
    owner: Optional[str] = None
    contact: Optional[str] = None
    ip_notice: Optional[bool] = None
    liability_clause: Optional[bool] = None
    applicable_law: Optional[str] = None
    def merge(self, o: "LegalNoticeDetails") -> None:
        for k in ("owner","contact","applicable_law"):
            if getattr(o,k) and not getattr(self,k):
                setattr(self,k,getattr(o,k))
        if o.ip_notice is True:
            self.ip_notice = True
        if o.liability_clause is True:
            self.liability_clause = True

class DataProtectionDetails(BaseModel):
    dpo_contact: Optional[str] = None
    rights: Rights = Rights()
    rights_general_statement: Optional[bool] = None
    source_of_data: Optional[str] = None
    retention: Optional[str] = None
    recipients: List[str] = Field(default_factory=list)
    transfer_scope: Optional[str] = None
    automated_decisions: Optional[bool] = None
    complaint_authority: Optional[bool] = None
    def merge(self, o: "DataProtectionDetails") -> None:
        for k in ("recipients",):
            setattr(self, k, list(dict.fromkeys(getattr(self, k)+getattr(o, k))))
        for k in ("dpo_contact","source_of_data","retention"):
            if getattr(o,k) and not getattr(self,k):
                setattr(self,k,getattr(o,k))
        rank = {None: 0, "NONE": 1, "INTRA_EU": 2, "INTERNATIONAL": 3}
        if rank.get(o.transfer_scope, 0) > rank.get(self.transfer_scope, 0):
            self.transfer_scope = o.transfer_scope
        self.rights.merge(o.rights)
        if o.rights_general_statement is True:
            self.rights_general_statement = True
        if o.automated_decisions is True or self.automated_decisions is None:
            self.automated_decisions = o.automated_decisions
        if o.complaint_authority is True:
            self.complaint_authority = True

DOC_MODEL = {
    "PRIVACY_POLICY":  PrivacyDetails,
    "COOKIE_POLICY":   CookieDetails,
    "LEGAL_NOTICE":    LegalNoticeDetails,
    "DATA_PROTECTION": DataProtectionDetails,
}

_ACCEPT_PAT = re.compile(
    r"\b("
    r"acept\w*|"
    r"|accept\w*|"
    r"|agree|allow|ok|yes|continue|"
    r"|autoriser|accepter|"
    r"|akzept\w*|"
    r"|aceitar\w*"
    r")\b",
    flags=re.I | re.U
)

_REJECT_PAT = re.compile(
    r"\b("
    r"rechaz\w*|deneg\w*|declin\w*|"
    r"|reject\w*|deny\w*|"
    r"|refus\w*|"
    r"|ablehn\w*|"
    r"|recus\w*"
    r")\b",
    flags=re.I | re.U
)

_MORE_PAT = re.compile(
    r"\b("
    r"ver|leer|m[áa]s|"
    r"|show|read|more|"
    r")\b",
    flags=re.I | re.U
)

def infer_jurisdiction(url: str) -> str:
    host = ul.urlparse(url).netloc.lower()
    if ".gov.uk" in host: return "UK"
    if ".gov.au" in host: return "AU"
    if ".gob.mx" in host: return "MX"
    if ".gob.cl" in host: return "CL"
    if ".gov.za" in host: return "ZA"
    if host.endswith(".gov.in") or host.endswith(".nic.in") or ".gov.in" in host or ".nic.in" in host: return "IN"
    return "GEN"

def jurisdiction_hint(jur: str, lang: str, doc_type: str) -> str:
    es = (lang or "en").startswith("es")
    if es:
        if jur == "MX":
            return ("Marco: LGPDPPSO (sector público). Busca Aviso de Privacidad, derechos ARCO "
                    "(acceso/rectificación/cancelación/oposición) y cómo ejercerlos. Autoridad: "
                    "Secretaría Anticorrupción y Buen Gobierno / ‘Transparencia para el Pueblo’.")
        if jur == "CL":
            return ("Marco: Ley 19.628 (vigente) y nueva Ley 21.719 (LPPD) en transición hasta dic-2026. "
                    "Fíjate en responsable, finalidades, cesiones, derechos ARCO + portabilidad + bloqueo, "
                    "y canal ante la futura DPA.")
        if jur == "ZA":
            return ("Marco: POPIA. ‘Information Officer’ como contacto; derechos (acceso/corrección/borrado/"
                    "oposición; no solo decisiones automatizadas); transferencias (s.72); quejas ante "
                    "el Information Regulator.")
        if jur == "AU":
            return ("Marco: Privacy Act 1988 (APPs). Derechos típicos: acceso (APP12) y corrección (APP13); "
                    "transferencias (APP8). OAIC para quejas; políticas claras de privacidad y NDB scheme.")
        if jur == "UK":
            return ("Marco: UK GDPR + Data Protection Act 2018; cookies bajo PECR. Derechos: acceso, "
                    "rectificación, supresión, restricción, portabilidad, oposición y no decisiones "
                    "solo automatizadas. ICO como autoridad.")
        if jur == "IN":
            return ("Marco: DPDP Act 2023 (implementación pendiente). Busca Data Fiduciary/Grievance Officer, "
                    "derechos (acceso/corrección/actualización/borrado) y vía de queja al Data Protection Board.")
        return ""
    else:
        if jur == "MX":
            return ("Apply LGPDPPSO (public sector). Look for a Privacy Notice, ARCO rights and how to exercise "
                    "them. Authority is now the Secretariat for Anti-Corruption & Good Government / "
                    "‘Transparencia para el Pueblo’ (not INAI).")
        if jur == "CL":
            return ("Apply Chilean law: Law 19.628 (in force) and new Law 21.719 (LPPD) transitioning until Dec-2026. "
                    "Expect controller, purposes, disclosures, ARCO rights plus portability and blocking; DPA being set up.")
        if jur == "ZA":
            return ("Apply POPIA. Map ‘Information Officer’ to DPO contact; data subject rights (access/correction/"
                    "erasure/object; no solely automated decisions); cross-border under s.72; complaints to the Information Regulator.")
        if jur == "AU":
            return ("Apply Privacy Act 1988 (APPs). Expect access (APP12) and correction (APP13); cross-border under APP 8; "
                    "OAIC complaints; NDB scheme applies.")
        if jur == "UK":
            return ("Apply UK GDPR + Data Protection Act 2018; cookies under PECR. Rights include access, rectification, "
                    "erasure, restriction, portability, objection and limits on automated decisions. ICO is the regulator.")
        if jur == "IN":
            return ("Apply DPDP Act 2023 (not fully in force yet). Look for Data Fiduciary/Grievance Officer, rights "
                    "(access/correction/update/erasure) and complaints to the Data Protection Board.")
        return ""

def fetch(url: str, timeout: int = 30, accept_language: str | None = None) -> tuple[str, str]:
    sess = requests.Session()
    for attempt_url in (url, url.replace("https://", "http://")):
        try:
            r = sess.get(
                attempt_url,
                timeout=timeout,
                allow_redirects=True,
                headers={
                    "User-Agent": UA,
                    "Accept-Language": accept_language or "en-GB,en;q=0.9,es;q=0.6",
                    "Accept": (
                        "text/html,application/xhtml+xml,application/pdf;"
                        "q=0.9,text/plain;q=0.8,*/*;q=0.5"
                    ),
                },
            )

            if r.status_code == 403:
                    r = sess.get(
                        attempt_url,
                        timeout=timeout,
                        allow_redirects=True,
                        headers={**r.request.headers, "Referer": attempt_url},
                    )

            if not r.ok:
                    continue

            ctype = r.headers.get("Content-Type", "").split(";")[0].strip().lower()

            if ctype in {"text/html", "text/plain", "application/xhtml+xml"}:
                return r.text, ctype

            if ctype == "application/pdf":
                try:
                    import io
                    from pdfminer.high_level import extract_text
                    return extract_text(io.BytesIO(r.content)) or "", ctype
                except Exception as e:
                    print("Error PDF‑parse", attempt_url, e, file=sys.stderr)
                    return "", ctype

        except requests.RequestException as e:
            print("Error REQUEST", attempt_url, e, file=sys.stderr)
            continue

    return "", ""

def _click_if(page, pattern, timeout=2500):
    for el in page.locator("button, input[type=button], a, div[role=button]").all():
        try:
            txt = el.inner_text(timeout=300).strip()
        except PWTimeout:
            continue
        if pattern.search(txt):
            try:
                el.click(timeout=timeout)
                return True
            except PWTimeout:
                pass
    return False

def _safe_scroll_to_bottom(page):
    try:
        page.evaluate("""() => {
            const b = document && document.body;
            if (b) window.scrollTo(0, b.scrollHeight);
        }""")
    except Exception:
        pass

def _safe_scroll_height(page) -> int:
    try:
        return page.evaluate("""() => (document && document.body) ? document.body.scrollHeight : 0""")
    except Exception:
        return 0

def needs_render(html: str, plain: str) -> bool:
    words = len(plain.split())
    ratio = len(plain) / len(html) if html else 0
    return words < 300 and ratio < 0.05


def fetch_render(url: str, timeout: int = 30, accept_language: str | None = None) -> tuple[str, str]:
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
        page = browser.new_page(extra_http_headers={"Accept-Language": accept_language or "en-GB,en;q=0.9,es;q=0.6"})
        page.goto(url, wait_until="load", timeout=timeout * 1000)
        try:
            page.wait_for_load_state("networkidle", timeout=60000)
        except PWTimeout:
            pass
        _safe_scroll_to_bottom(page)
        page.wait_for_timeout(1200)
        _click_if(page, _ACCEPT_PAT) or _click_if(page, _REJECT_PAT)
        page.eval_on_selector_all(
            "details:not([open])",
            "(els) => els.forEach(e => e.open = true)"
        )
        for btn in page.locator("[aria-expanded='false']").all():
            try:
                btn.click(force=True, timeout=800)
            except Exception:
                pass
        if _click_if(page, _MORE_PAT):
            page.wait_for_timeout(1500)
        page.wait_for_timeout(500)

        prev_height = 0
        for _ in range(12):
            _safe_scroll_to_bottom(page)
            page.wait_for_timeout(1000)
            curr_height = _safe_scroll_height(page)
            if curr_height == prev_height:
                break
            prev_height = curr_height

        html = page.content()
        mime = "text/html"
        if looks_like_acceda_stub(html):
            page.wait_for_timeout(1000)
            html = page.content()

        browser.close()
        return html, mime

def extract_text(html:str)->str:
    soup = BeautifulSoup(html, "lxml")
    main = (
        soup.find("main")
        or soup.find(attrs={"role": "main"})
        or soup
    )
    for tag in main(
        [
            "script",
            "style",
            "noscript",
            "header",
            "footer",
            "nav",
            "aside",
            "form",
        ]
    ):

        tag.decompose()
    for el in main.select('[aria-hidden="true"], [style*="display:none"]'):
        el.decompose()
    lines = (
        line.strip()
        for line in main.get_text(" ", strip=True).splitlines()
        if line.strip()
    )
    clean = "\n".join(dict.fromkeys(lines))

    return clean

def _accept_language_for(lang: str | None) -> str:
    grp = (lang or "en").split("-")[0].lower()
    if grp == "es": return "es-ES,es;q=0.9,en;q=0.6"
    if grp == "hi": return "hi-IN,hi;q=0.9,en;q=0.6"
    if grp == "ml": return "ml-IN,ml;q=0.9,en;q=0.6"
    return "en-GB,en;q=0.9,es;q=0.6"

def looks_like_acceda_stub(html: str) -> bool:
    soup = BeautifulSoup(html, "lxml")

    if len(soup.get_text(" ", strip=True).split()) > 200:
        return False

    if soup.find("noscript", string=re.compile("JavaScript desactivado", re.I)):
        return True
    if soup.find("script",  string=re.compile(r"window\.location", re.I)):
        return True
    if soup.find("meta",    attrs={"http-equiv": re.compile("refresh", re.I)}):
        return True

    return False


def split_chunks(text:str)->List[str]:
    words=text.split(); res=[]; i=0
    while i<len(words):
        res.append(" ".join(words[i:i+CHUNK_TOKENS])); i+=CHUNK_TOKENS-CHUNK_OVERLAP
    return res

FIELD_DEFS_ES = {
    "PRIVACY_POLICY": """\
Campos que debes devolver en JSON → details
{
  "controller": "Nombre completo o razón social de la entidad responsable del tratamiento de datos.",
  "dpo_contact": "Correo electrónico, teléfono o formulario de contacto específico del Delegado de Protección de Datos (DPD) o del punto de contacto para cuestiones de privacidad. Si no existe, puede quedar vacío.",
  "purposes": "Lista de las finalidades específicas para las que se recogen y tratan los datos (ej. 'gestión de usuarios', 'marketing', 'envío de newsletters', 'mejora del servicio'). Deben ser descripciones claras y concisas.",
  "legal_bases": "Lista literal de las bases jurídicas que legitiman el tratamiento de los datos, tal como aparecen en el documento (ej. 'consentimiento', 'ejecución de un contrato', 'cumplimiento de una obligación legal', 'interés legítimo', 'misión en interés público').",
  "source_of_data": "Texto descriptivo si los datos personales no se han obtenido directamente del interesado, indicando la fuente (ej. 'directorios públicos', 'otras empresas del grupo'). Si no se menciona o se asume la recogida directa, este campo puede ser nulo o vacío.",
  "retention": "Plazo o criterio de conservación de los datos (ej. '5 años', 'mientras sea necesario para la finalidad', 'hasta la revocación del consentimiento', 'según plazos legales'). Si hay múltiples plazos, elige el más representativo o incluye los criterios generales.",
  "recipients": "Lista de nombres de empresas, categorías de servicios (ej. 'proveedores de servicios de hosting', 'agencias de marketing') o tipos de autoridades (ej. 'autoridades fiscales', 'fuerzas de seguridad') a los que se ceden o transfieren datos.",
  "transfer_scope": "Indica el ámbito geográfico de las transferencias de datos. Valora si se mencionan transferencias fuera del Espacio Económico Europeo. Opciones: 'NONE' (no se mencionan transferencias fuera del ámbito del controlador), 'INTRA_EU' (transferencias solo dentro de la UE/EEE), 'INTERNATIONAL' (transferencias a países fuera del EEE), 'null' si no se menciona.",
  "rights": "Objeto con claves booleanas para cada derecho del interesado (acceso, rectificación, oposición, supresión/olvido, limitación del tratamiento, portabilidad y no ser objeto de decisiones individualizadas). Establece 'true' si el documento nombra explícitamente el derecho y existe referencia a su ejercicio (formulario, sede electrónica, correo postal, correo electrónico, teléfono, expresión genérica...), 'false' en caso contrario. ("access": "bool|null", "rectification": "bool|null", "erasure": "bool|null", "opposition": "bool|null", "portability": "bool|null", "restriction": "bool|null", "no_individual_decision": "bool|null").",
  "rights_general_statement": "Booleano (true|null) que indica si sólo se menciona en bloque la posibilidad de ejercer los derechos de protección de datos sin enumerarlos.",
  "automated_decisions": "Booleano que indica si se mencionan perfiles ('profiling') o decisiones basadas únicamente en el tratamiento automatizado de datos que produzcan efectos jurídicos o afecten significativamente al interesado. 'true' si se menciona, 'false' si no."
}""",
    "COOKIE_POLICY": """\
Campos → details
{
  "ownership": "Clasificación de las cookies por su propietario. Opciones: 'FIRST' (solo cookies propias), 'THIRD' (solo cookies de terceros), 'MIXED' (ambas), 'null'.",
  "third_parties": "Lista de nombres específicos de proveedores de terceros cuyas cookies se utilizan (ej. 'Google Analytics', 'Facebook Pixel', 'Adobe Analytics').",
  "types": "Lista de las categorías de cookies utilizadas (ej. 'técnica', 'analítica', 'publicitaria', 'personalización', 'funcional').",
  "purpose": "Lista de las finalidades o funciones explicadas para el uso de cookies (ej. 'medición de audiencia', 'mostrar anuncios personalizados', 'recordar preferencias de idioma').",
  "duration": "Duración general o predominante de las cookies ("session": bool|null, "persistent": bool|null, "max_exp": "Texto como '30d', '1y', 'until_logout'... o null").",
  "consent_mechanism": "Mecanismo por el cual se obtiene el consentimiento del usuario para las cookies. Opciones: 'banner' (aviso de cookies o banner), 'cmp' (plataforma de gestión de consentimiento), 'scroll' (asume el consentimiento al hacer scroll, no recomendado), 'none' (no se menciona un mecanismo claro).",
  "mgmt_instructions": "Booleano (true|null) que indica si se proporcionan instrucciones para gestionar o desactivar las cookies (ej. configuración del navegador, panel de preferencias). 'true' si las hay, 'null' si no."
}""",
    "LEGAL_NOTICE": """\
Campos → details
{
  "owner": "Nombre de la empresa, persona física o entidad propietaria del sitio web.",
  "contact": "Información de contacto general del propietario (correo electrónico, número de teléfono).",
  "ip_notice": "Booleano que indica si se menciona una advertencia sobre la propiedad intelectual o los derechos de autor (ej. cláusulas de copyright). 'true' si se incluye, 'false' si no.",
  "liability_clause": "Booleano que indica si existe una cláusula de exención o limitación de responsabilidad del titular del sitio web. 'true' si se incluye, 'false' si no.",
  "applicable_law": "Identifica la legislación que rige el aviso legal y, si se menciona, los tribunales competentes para cualquier disputa."
}""",
    "DATA_PROTECTION": """\
Campos → details
{
  "dpo_contact": "Información de contacto del DPD (correo, teléfono). Similar al de la Política de Privacidad, pero relevante para un documento más técnico o interno.",
  "source_of_data": "Texto descriptivo si los datos proceden de terceros. Idéntico al campo en PRIVACY_POLICY.",
  "recipients": "Lista de terceros/autoridades a los que se ceden/transfieren datos. Idéntico al campo en PRIVACY_POLICY.",
  "transfer_scope": "Ámbito geográfico de las transferencias de datos. Idéntico al campo en PRIVACY_POLICY.",
  "retention": "Plazo o criterio de conservación de los datos. Idéntico al campo en PRIVACY_POLICY.",
  "rights": "Objeto booleano que indica la mención de los derechos de los interesados ((acceso, rectificación, oposición, supresión/olvido, limitación del tratamiento, portabilidad y no ser objeto de decisiones individualizadas). Idéntico al campo en PRIVACY_POLICY.",
  "rights_general_statement": "Booleano (true|null) que indica si sólo se menciona en bloque la posibilidad de ejercer los derechos de protección de datos sin enumerarlos.",
  "automated_decisions": "Booleano que indica si se mencionan perfiles o decisiones automatizadas. Idéntico al campo en PRIVACY_POLICY.",
  "complaint_authority": "Booleano que indica si se menciona explícitamente el derecho a presentar una reclamación ante una autoridad de control (ej. AEPD en España). 'true' si se especifica esta posibilidad, 'false' si no."
}"""
}

FIELD_DEFS_EN = {
    "PRIVACY_POLICY": """\
Fields to return in JSON → details
{
  "controller": "Full name or legal name of the entity responsible for data processing.",
  "dpo_contact": "Email, phone number, or specific contact form for the Data Protection Officer (DPO) or the privacy contact point. Can be empty if not applicable.",
  "purposes": "List of specific purposes for which personal data is collected and processed (e.g., 'user management', 'marketing', 'newsletter sending', 'service improvement'). Descriptions should be clear and concise.",
  "legal_bases": "Literal list of the legal bases that legitimize data processing, as they appear in the document (e.g., 'consent', 'contract performance', 'legal obligation', 'legitimate interest', 'public interest task').",
  "source_of_data": "Descriptive text if personal data has not been obtained directly from the data subject, indicating the source (e.g., 'public directories', 'other group companies'). If not mentioned or direct collection is assumed, this field can be null or empty.",
  "retention": "Data retention period or criteria (e.g., '5 years', 'as long as necessary for the purpose', 'until consent is revoked', 'according to legal deadlines'). If multiple periods, choose the most representative or include general criteria.",
  "recipients": "List of names of companies, categories of services (e.g., 'hosting service providers', 'marketing agencies'), or types of authorities (e.g., 'tax authorities', 'law enforcement') to whom data is disclosed or transferred.",
  "transfer_scope": "Indicates the geographical scope of data transfers. Assess whether transfers outside the European Economic Area are mentioned. Options: 'NONE' (no transfers outside the controller's scope are mentioned), 'INTRA_EU' (transfers only within the EU/EEA), 'INTERNATIONAL' (transfers to countries outside the EEA), 'null' (not clearly specified).",
  "rights": "Object with boolean keys for each data subject's right (access, rectification, erasure/right to be forgotten, restriction, data portability, objection, not to be subject to automated decision-making). Set 'true' if the document explicitly names the right and there is any reference to how it can be exercised (web form, e-office, postal mail, e-mail, phone number, or a generic wording such as “you may submit a request”), 'false' otherwise. ("access": "bool|null", "rectification": "bool|null", "erasure": "bool|null", "opposition": "bool|null", "portability": "bool|null", "restriction": "bool|null", "no_individual_decision": "bool|null"). ",
  "rights_general_statement": "Boolean (true|null) indicating whether the ability to exercise data protection rights is only mentioned in bulk without enumerating them.",
  "automated_decisions": "Boolean indicating whether profiling or decisions based solely on automated data processing that produce legal effects or significantly affect the data subject are mentioned. 'true' if mentioned, 'false' if not."
}""",
    "COOKIE_POLICY": """\
Fields → details
{
  "ownership": "Classification of cookies by their owner. Options: 'FIRST' (only first-party cookies), 'THIRD' (only third-party cookies), 'MIXED' (both), 'null'.",
  "third_parties": "List of specific names of third-party providers whose cookies are used (e.g., 'Google Analytics', 'Facebook Pixel', 'Adobe Analytics').",
  "types": "List of cookie categories used (e.g., 'technical', 'analytical', 'advertising', 'personalization', 'functional').",
  "purpose": "List of the explained purposes or functions for cookie usage (e.g., 'audience measurement', 'display personalized ads', 'remember language preferences').",
  "duration": "General or predominant duration of the cookies ("session": bool|null, "persistent": bool|null, "max_exp": "Text like '30d', '1y', 'until_logout'... or null").",
  "consent_mechanism": "Mechanism by which user consent for cookies is obtained. Options: 'banner' (cookie notice or banner), 'cmp' (Consent Management Platform), 'scroll' (assumes consent by scrolling, not recommended), 'none' (no clear mechanism mentioned).",
  "mgmt_instructions": "Boolean indicating whether instructions for managing or disabling cookies are provided (e.g., browser settings, preferences panel). 'true' if provided, 'false' if not."
}""",
    "LEGAL_NOTICE": """\
Fields → details
{
  "owner": "Name of the company, individual, or entity owning the website.",
  "contact": "General contact information for the owner (email, phone number).",
  "ip_notice": "Boolean indicating whether a warning about intellectual property or copyright is mentioned (e.g., copyright clauses). 'true' if included, 'false' if not.",
  "liability_clause": "Boolean indicating whether a disclaimer or limitation of liability clause for the website owner exists. 'true' if included, 'false' if not.",
  "applicable_law": "Identifies the legislation governing the legal notice and, if mentioned, the competent courts for any disputes."
}""",
    "DATA_PROTECTION": """\
Fields → details
{
  "dpo_contact": "DPO contact information (email, phone). Similar to Privacy Policy, but relevant for a more technical or internal document.",
  "source_of_data": "Descriptive text if data comes from third parties. Identical to the field in PRIVACY_POLICY.",
  "recipients": "List of third parties/authorities to whom data is transferred/disclosed. Identical to the field in PRIVACY_POLICY.",
  "transfer_scope": "Geographical scope of data transfers. Identical to the field in PRIVACY_POLICY.",
  "retention": "Data retention period or criteria. Identical to the field in PRIVACY_POLICY.",
  "rights": "Boolean object indicating the mention of data subjects' rights (access, rectification, erasure, restriction, data portability, objection, not to be subject to automated decision-making). Identical to the field in PRIVACY_POLICY.",
  "rights_general_statement": "Boolean (true|null) indicating whether the ability to exercise data protection rights is only mentioned in bulk without listing them.",
  "automated_decisions": "Boolean indicating whether profiling or automated decisions are mentioned. Identical to the field in PRIVACY_POLICY.",
  "complaint_authority": "Boolean indicating whether the right to lodge a complaint with a supervisory authority (e.g., AEPD in Spain) is explicitly mentioned. 'true' if this possibility is specified, 'false' if not."
}"""
}

def build_prompt(doc_type: str, chunk: str, lang: str, jur_hint: str = "") -> str:
    if lang == "es":
        base = "Eres un auditor experto en RGPD."
        instr  = "Analiza el documento y responde EXCLUSIVAMENTE con el objeto JSON bajo la clave `details`, sin comentarios ni código markdown. **IMPORTANTE → Usa EXACTAMENTE las claves y los tipos indicados abajo. No uses null para listas u objetos; si el documento guarda silencio usa [] o {}.**"
        label  = "# CONTENIDO DEL DOCUMENTO ↓"
        schema = FIELD_DEFS_ES[doc_type]
    elif lang == "en":
        base = "You are a senior GDPR auditor."
        instr  = "Parse the document and respond EXCLUSIVELY with the JSON object under the `details` key, without comments or Markdown code. **IMPORTANT → Use EXACTLY the keys and types indicated below. Don't use null for lists or objects; if the document is silent, use [] or {}.**"
        label  = "# DOCUMENT CONTENT ↓"
        schema = FIELD_DEFS_EN[doc_type]
    else:
        base = "You are a senior privacy‑law auditor."
        instr  = "Analyse the document and respond EXCLUSIVELY with JSON object under the key `details`, without comments or markdown code. **IMPORTANT → Use EXACTLY the keys and types specified below. Don't use null for lists or objects; if the document is silent, use [] or {}.**"
        label  = "# DOCUMENT CONTENT ↓"
        schema = FIELD_DEFS_EN[doc_type]

    header = f"{base}\n{jur_hint}".strip()

    return f"{header}\n{instr}\n\n{schema}\n\n{label}\n{chunk[:10000]}"

class RateLimiter:
    def __init__(self, per_min: int, per_sec: int = 1):
        self.per_min = max(1, per_min)
        self.per_sec = max(1, per_sec)
        self._min_win = collections.deque()
        self._sec_win = collections.deque()
        self._lock = threading.Lock()

    def acquire(self):
        now = _time.time()
        while True:
            with self._lock:
                while self._min_win and now - self._min_win[0] >= 60:
                    self._min_win.popleft()
                while self._sec_win and now - self._sec_win[0] >= 1:
                    self._sec_win.popleft()

                if len(self._sec_win) < self.per_sec and len(self._min_win) < self.per_min:
                    self._sec_win.append(now)
                    self._min_win.append(now)
                    return

                wait_sec = 0.0
                if self._sec_win:
                    wait_sec = max(0.0, 1 - (now - self._sec_win[0]) + 0.01)
                wait_min = 0.0
                if self._min_win:
                    wait_min = max(0.0, 60 - (now - self._min_win[0]) + 0.01)
                sleep_for = max(wait_sec, wait_min, 0.05)

            _time.sleep(sleep_for)
            now = _time.time()

class DailyQuotaExceeded(RuntimeError): pass
stop_event = threading.Event()

def call_llm(prompt:str,provider:str,model:str,lim:RateLimiter,dbg=False)->str:
    lim.acquire()
    if provider=="gemini":
        client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))
        current = model
        for i in range(MAX_RETRIES_LLM):
            if stop_event.is_set():
                return ""
            try:
                resp=client.models.generate_content(model=current, contents=[{"role":"user","parts":[{"text": prompt}]}], config={"temperature": 0})
                return (getattr(resp, "text", "") or "").strip()
            except Exception as e:
                msg = str(e).lower()
                if dbg: print("[gemini]",e,file=sys.stderr)
                if any(k in msg for k in ("quota","429","resource_exhausted","rate","exceeded")):
                    if "2.5-pro" in current:      current = current.replace("2.5-pro","2.5-flash")
                    elif "2.5-flash" in current:  current = "gemini-2.0-flash"
                    else:
                        stop_event.set()
                        raise DailyQuotaExceeded()
                    continue
                time.sleep(1.5**i + random.random())
    else:
        import openai
        client=openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        for i in range(MAX_RETRIES_LLM):
            try:
                chat=client.chat.completions.create(model=model,messages=[{"role":"user","content":prompt}])
                return (chat.choices[0].message.content or "").strip()
            except Exception as e:
                if dbg: print("[openai]",e,file=sys.stderr)
                time.sleep(2**i)
    return ""

class Link(BaseModel):
    domain:str; url:str; doc_type:str; anchor_text:str|None; lang:str|None

def _empty_if_silence(v):
    if isinstance(v, str) and _SILENCE_PAT.match(v):
        return ""
    return v

def _list_or_empty(v):
    if v is None:
        return []
    if isinstance(v, str):
        s = v.strip()
        return [] if not s or _SILENCE_PAT.match(s) else [s]
    if isinstance(v, dict):
        return list(v.values())
    if isinstance(v, list):
        return v
    return []

def _to_bool_or_none(v):
    if isinstance(v, bool): return v
    if isinstance(v, str):
        t = v.strip().lower()
        if t in {"true","1","yes","sí","si"}: return True
        if t in {"false","0","no"}: return False
    return None

def sanitize_raw(raw: dict, doc_type: str) -> dict:
    if not isinstance(raw, dict):
        return {}

    STRING_FIELDS = {
        "LEGAL_NOTICE":  ("owner", "contact", "applicable_law"),
        "PRIVACY_POLICY": ("controller", "dpo_contact", "source_of_data", "retention"),
        "DATA_PROTECTION": ("dpo_contact", "source_of_data", "retention"),
    }

    LIST_FIELDS = {
        "COOKIE_POLICY":  ("third_parties", "types", "purpose"),
        "PRIVACY_POLICY": ("purposes", "legal_bases", "recipients"),
        "DATA_PROTECTION": ("recipients",),
    }

    MUST_HAVE_OBJ = {
        "COOKIE_POLICY": ("duration",),
        "PRIVACY_POLICY": ("rights",),
        "DATA_PROTECTION": ("rights",),
    }

    for f in STRING_FIELDS.get(doc_type, ()):
        val = _empty_if_silence(raw.get(f))
        if val in (None, [], {}):
            raw[f] = ""

        elif not isinstance(val, str):
            raw[f] = str(val)
        else:
            raw[f] = val

    for f in LIST_FIELDS.get(doc_type, ()):
        raw[f] = _list_or_empty(raw.get(f))

    if "rights" in raw:
        if isinstance(raw["rights"], bool) or raw["rights"] is None:
            raw["rights"] = {}

    if "rights" in raw and isinstance(raw["rights"], dict):
        for k, v in list(raw["rights"].items()):
            vv = _to_bool_or_none(v)
            raw["rights"][k] = None if vv is False else (True if vv is True else None)

    if doc_type == "COOKIE_POLICY":
        dur = raw.get("duration")
        if dur is None or not isinstance(dur, dict):
            raw["duration"] = {"session": None, "persistent": None, "max_exp": None}
        else:
            raw["duration"].setdefault("session", None)
            raw["duration"].setdefault("persistent", None)
            raw["duration"].setdefault("max_exp", None)

    for key in MUST_HAVE_OBJ.get(doc_type, ()):
        raw.setdefault(key, {})

    ALLOWED = set(DOC_MODEL[doc_type].model_fields.keys())
    for key in list(raw.keys()):
        if key not in ALLOWED:
            raw.pop(key, None)

    return raw

def audit_one(link:Link,prov,model,lim,dbg=False)->dict|None:
    if stop_event.is_set(): return None

    if dbg:
        print("-", link.doc_type, link.url)
        sys.stdout.flush()

    acc = _accept_language_for(link.lang)
    html, mime = fetch(link.url, accept_language=acc)

    force_render = mime == "text/html" and looks_like_acceda_stub(html)
    if mime == "text/html":
        plain = extract_text(html)
        if needs_render(html, plain) or force_render:
            if dbg: print("render JS (SPA heuristics)")
            try:
                html, mime = fetch_render(link.url, accept_language=acc)
                plain = extract_text(html)
            except PWTimeout:
                if dbg:
                    print("Render timeout – fallback to raw HTML")
                html, mime = fetch(link.url, accept_language=acc)
                plain = extract_text(html)
    else:
        plain = html

    text = plain

    if not html:
        if dbg: print("Error FETCH (raw) --> trying render", link.url[:100])
        try:
            html, mime = fetch_render(link.url, accept_language=acc)
            plain = extract_text(html) if mime == "text/html" else html
        except Exception as e:
            if dbg: print("Error RENDER fallback failed:", e)
            return None
    if not text:
        text = BeautifulSoup(html, "lxml").get_text(" ", strip=True)
    if not text.strip():
        if dbg: print("Error EMPTY‑TEXT", link.url[:100])
        return None
    combined: BaseModel | None = None
    last_raw={}
    for chunk_no, chunk in enumerate(split_chunks(text), 1):
        if stop_event.is_set(): break
        if dbg:
            print(f"  chunk {chunk_no}, {len(chunk.split())}words")

        jur = infer_jurisdiction(link.url)
        hint = jurisdiction_hint(jur, link.lang or "en", link.doc_type)

        prompt = build_prompt(link.doc_type, chunk, link.lang, hint)

        try:
            schema = schema_of(link.doc_type)
            data = gemini_json(model, prompt, schema)
            raw_response = data.get("details", data)

        except Exception as e:
            if dbg: print("schema JSON failed; fallback --> text balance:", e)
            raw_txt = call_llm(prompt, prov, model, lim, dbg)
            try:
                parsed = json.loads(find_balanced_json(raw_txt))
            except Exception:
                parsed = {}
            raw_response = parsed.get("details", parsed)

        last_raw = sanitize_raw(raw_response, link.doc_type)

        if not last_raw:
            if dbg: print("Empty answer")
            continue
        try:
            obj=DOC_MODEL[link.doc_type](**last_raw)
        except ValidationError as e:
            if dbg:
                print("Error VALIDATION", e.errors()[0]["msg"])
                print("- returned:", json.dumps(last_raw, ensure_ascii=False)[:300], "…")
            continue
        except Exception:
            continue
        if combined is None: combined=obj
        else: combined.merge(obj)

    if combined is None:
        return None
    return {
        "domain": link.domain,
        "url": link.url,
        "doc_type": link.doc_type,
        "lang": link.lang,
        "last_update": last_raw.get("last_update","NO_DATE"),
        "details": combined.model_dump(),
        "sha1": hashlib.sha1(link.url.encode()).hexdigest(),
    }

def safe_json_line(text: str) -> dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(find_balanced_json(text))

def main():
    ap=argparse.ArgumentParser(description="Audit policy docs with Gemini/OpenAI (NDJSON out)")
    ap.add_argument("--links",required=True)
    ap.add_argument("--output",required=True)
    ap.add_argument("--provider",choices=["gemini","openai"],default="gemini")
    ap.add_argument("--model",default="gemini-2.5-pro")
    ap.add_argument("--rate",type=int,default=8)
    ap.add_argument("--parallel",type=int,default=1)
    ap.add_argument("--debug",action="store_true")
    ns=ap.parse_args()

    links: List[Link] = []
    with open(ns.links, encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            links.append(Link(**safe_json_line(raw)))

    out_p=Path(ns.output); out_p.parent.mkdir(parents=True,exist_ok=True)

    done_hashes = load_done_hashes(out_p)

    todo = [l for l in links if link_hash(l) not in done_hashes]
    if ns.debug:
        print(f"Skipping {len(done_hashes)} already processed; pending: {len(todo)}")

    VALID = {"gemini-1.5-flash","gemini-1.5-pro","gemini-2.0-flash","gemini-2.5-flash","gemini-2.5-pro"}
    if ns.model not in VALID:
        sys.exit(f"Non-supported model: {ns.model}. Supported: {', '.join(VALID)}")

    FREE_RPM = {"gemini-1.5-flash":15,"gemini-1.5-pro":10,"gemini-2.0-flash":10,"gemini-2.5-flash":10,"gemini-2.5-pro":5}
    limiter = RateLimiter(min(ns.rate, FREE_RPM[ns.model]))

    done=0
    with out_p.open("a", encoding="utf-8") as fout, ThreadPoolExecutor(max_workers=ns.parallel) as pool:
        futs = {pool.submit(audit_one, l, ns.provider, ns.model, limiter, ns.debug): l for l in todo}
        for fut in as_completed(futs):
            try:
                res = fut.result()
                if res:
                    fout.write(json.dumps(res, ensure_ascii=False) + "\n")
                    fout.flush()
                    os.fsync(fout.fileno())
                    done += 1
            except DailyQuotaExceeded:
                for f in futs:
                    f.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return
    print(f"OK audit: {done}/{len(links)} documentos → {out_p}")

if __name__ == "__main__":
    main()
