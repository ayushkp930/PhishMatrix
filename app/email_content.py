"""Contextual rules over decoded, current-message prose. Keep excerpts from before normalization."""
import re
from app.email_unicode import INVISIBLE, canonical_text, codepoints, skeleton

FINANCE = re.compile(r"\b(?:invoice|remittance|neft|rtgs|imps|iban|swift|ifsc|account number|beneficiary|settlement|payment|wire transfer)\b", re.I)
DEST = r"(?:bank(?:ing)?\s+(?:account|details|coordinates|instructions)|beneficiary|remittance (?:details|instructions)|payment (?:account|details|instructions)|account (?:number|details)|iban|swift|ifsc)"
CHANGE = r"(?:new|updated?|revised?|changed?|replacement|different|amended|switched)"
BANK = re.compile(rf"\b{CHANGE}\s+(?:(?:our|the|your|vendor['’]s)\s+)?{DEST}\b|\b{DEST}\s+(?:(?:has|have|was|were|been|is|are|now)\s+){{0,4}}{CHANGE}\b", re.I)
INDIRECT = re.compile(r"\b(?:updated|revised|new|changed)\s+(?:details|mandate)\b", re.I)
PAY_ACTION = re.compile(r"\b(?:process|send|make|release|arrange|redirect|transfer|wire|remit|use)\s+(?:(?:the|this|your|our|a|all|future|outstanding)\s+){0,3}(?:payments?|funds|balance|transfer|remittance|NEFT|RTGS|IMPS)\b", re.I)
PRESSURE = re.compile(r"\b(?:urgent(?:ly)?|confidential|keep (?:this|it) (?:private|between us)|do not (?:call|discuss)|within (?:\d{1,2}|two) hours?|(?:clear (?:the )?|dispatch )hold|account suspension|immediately)\b", re.I)
WIRE = re.compile(r"\b(?:please\s+)?(?:initiate|make|send|authorize|complete|arrange|release)\s+(?:(?:a|the|this|an|urgent|confidential)\s+){0,3}(?:wire transfer|wire payment|bank transfer)\b", re.I)
CREDENTIAL_ENTRY = re.compile(r"\b(?:enter|confirm|submit|verify)\s+your\s+(?:current\s+)?(?:password|credentials|one[- ]time (?:pass)?code|otp)\b", re.I)
MANDATE = re.compile(r"\b(?:attached|enclosed)\s+(?:(?:revised|updated|bank|signed|new)\s+){0,3}(?:mandate(?: letter)?|invoice|bank details)\b|\b(?:mandate letter|invoice)\s+(?:is\s+)?attached\b", re.I)
GUARD = re.compile(r"\b(?:never|do not (?:send|change|pay|use|update|process)|don't (?:send|change|pay|use)|(?:have|has) not (?:changed|updated)|unchanged|no change|anti[- ]fraud|phishing (?:example|training)|beware of|fraud awareness|example of a scam)\b", re.I)
FORWARDED = re.compile(r"^(?:On .{1,400} wrote:|-+\s*(?:forwarded message|original message)\s*-+|Begin forwarded message:)$", re.I)
HIDDEN_WORDS = {"invoice","neft","rtgs","imps","password","beneficiary","iban","swift","ifsc","otp","remittance","verify"}
OBF_WORD = re.compile(r"[\w\u200b\u200c\u200d\u00ad\u202e]+")
BANK_CODE = re.compile(r"\b(IFSC|IBAN)\s*[:#-]?\s+(\w{8,34})\b", re.I)


def current_lines(text):
    for line in text.splitlines():
        if FORWARDED.fullmatch(line.strip()):
            break
        if not line.lstrip().startswith(">"):
            yield line


def inspect_prose(ev, parts, has_attachment, credential_reply, credential_deadline):
    pressure = mandate = wire = None
    for source, raw in parts:
        # Adjacent lines may form one instruction. Break at paragraph and sentence boundaries.
        for paragraph in re.split(r"\n\s*\n", "\n".join(current_lines(raw))):
            sentences = re.split(r"(?<=[.!?])\s+", paragraph)
            prior = ""
            for sentence in sentences:
                value = canonical_text(sentence)
                if GUARD.search(value):
                    prior = ""
                    continue
                if credential_deadline(value):
                    ev.add("EMAIL_CREDENTIAL_DEADLINE", source, sentence)
                entry = CREDENTIAL_ENTRY.search(value)
                if entry and not re.search(r"\b(?:do not|don.t|should not)\b", value, re.I) and (
                    ev.rows.keys() & {"EMAIL_LINK_MISMATCH", "EMAIL_HOMOGRAPH", "EMAIL_LINK_IMPERSONATION"}
                    or ev.rows.get("EMAIL_URL_STRUCTURE", {}).get("points", 0) >= 18
                ):
                    ev.add("EMAIL_CREDENTIAL_PORTAL", source, sentence)
                for line in current_lines(sentence):
                    if credential_reply(canonical_text(line).strip()):
                        ev.add("EMAIL_CREDENTIAL_REPLY", source, line.strip())
                for m in OBF_WORD.finditer(sentence):
                    word = m[0]
                    if any(c in INVISIBLE for c in word) and canonical_text(word).casefold() in HIDDEN_WORDS:
                        ev.add("EMAIL_HIDDEN_KEYWORD", source, word, codepoints=codepoints(word), visual_target=canonical_text(word))
                for m in BANK_CODE.finditer(sentence):
                    code = m[2]
                    shape = skeleton(code).upper()
                    if not code.isascii() and re.fullmatch(r"[A-Z0-9]+", shape):
                        ev.add("EMAIL_CODE_SPOOF", source, m[0], codepoints=codepoints(code), visual_target=shape)
                # Allow a nearby payment instruction to disambiguate "updated details".
                context = canonical_text(prior[-200:] + " " + sentence[:300])
                change = BANK.search(value)
                if change and (FINANCE.search(value) or re.search(r"\b(?:our|the|use|to|have changed|has changed)\b", value, re.I)):
                    ev.add("BEC_BANK_DETAIL_CHANGE", source, sentence if len(sentence) <= 320 else change[0])
                elif INDIRECT.search(context) and FINANCE.search(context) and PAY_ACTION.search(context):
                    ev.add("BEC_BANK_DETAIL_CHANGE", source, (prior[-140:] + " " + sentence[:178]).strip())
                if PRESSURE.search(value):
                    pressure = (source, sentence)
                if WIRE.search(value):
                    wire = (source, sentence)
                if MANDATE.search(value):
                    mandate = (source, sentence)
                prior = sentence
    if pressure and (wire or "BEC_BANK_DETAIL_CHANGE" in ev.rows):
        ev.add("BEC_EXECUTIVE_PRESSURE", *pressure, weight=28 if wire and "BEC_BANK_DETAIL_CHANGE" not in ev.rows else 18)
    if mandate and not has_attachment:
        ev.add("BEC_MISSING_MANDATE", *mandate, weight=9 if "BEC_BANK_DETAIL_CHANGE" in ev.rows else 0)
