"""A council of disciplinary reviewers for hypothesis generation.

Why this exists
---------------
Flow 3 asked a good question and answered it with one voice. A single drafting
call at low temperature, scored by arithmetic over the rows it cited, produces
the model's *modal* view of the subject -- which for AI security is the
consensus of the training corpus: memorization, jailbreak, RAG poisoning. That
list is not wrong. It is the part of the field every paper already covers, so a
hypothesis set built that way re-derives the literature instead of testing
anything.

Real review panels are not one voice sampled repeatedly. They are distinct
disciplines with distinct training, distinct instruments, and -- the part that
matters -- distinct blind spots. Each notices what the others cannot, and the
panel's disagreements are half the information content.

This module is that panel, as deterministic engine code rather than a prompt:

* :data:`SEATS` -- named reviewers, each owning a slice of the attack
  taxonomy and each declaring the weakness it is *known* to have. A panel that
  publishes its own blind spots is auditable; one that claims completeness is
  not.
* :func:`draft_seat_claims` -- per-seat drafting, grounded in the stored rows
  of flows 1 and 2. Never invents; a seat with no evidence stays silent.
* :func:`cross_examine` -- the adversarial pass. Every claim is attacked by the
  seats that do not own it, on grounds that can be checked mechanically:
  unfalsifiable test, self-graded magnitude, rival explanation the experiment
  cannot exclude, single-flow support, assertion a finding denies.
* :func:`falsifier_audit` -- grades a refutation test on whether it names an
  observation and a threshold, not merely on being non-empty.
* :func:`coverage_matrix` -- attack class x claim. Classes with no claim are
  reported ``unexamined``, which is emphatically not ``safe``.
* :func:`panel_disagreement` -- inter-seat agreement on the claims they
  contested, reusing the existing Gwet's AC1 machinery.

Nothing here raises, invents evidence, or reaches the network. A council that
needs a gateway to exist is a council that disappears exactly when it is
needed. The seats always run; the model only ever adds to them.
"""
from __future__ import annotations

import re
from typing import Any

#: Flow-1 dimensions and flow-2 dimensions, mapped onto the shared attack
#: taxonomy in :mod:`app.model_eval`. Both prior flows are re-expressed in one
#: vocabulary so the panel can ask "which slice of the field is nobody
#: covering" -- a question neither flow's own output can answer about itself.
_DIMENSION_CLASSES: dict[str, tuple[str, ...]] = {
    "training_data_privacy": ("membership_inference", "extraction",
                              "memorization"),
    "model_integrity": ("poisoning", "theft"),
    "deployment_surface": ("injection", "cascade"),
    "capability_abuse": ("theft", "injection"),
    "data_recon": ("extraction", "inversion", "membership_inference"),
    "evasion": ("evasion", "injection"),
    "manipulation": ("evasion", "poisoning"),
    "abuse_persistence": ("memorization", "alignment_data_leakage"),
    # ``governance`` is deliberately absent. A governance finding records what
    # is documented or undisclosed, not the observable signature of an attack,
    # and mapping it onto a class made the panel draft an alignment-leakage
    # claim from a missing model card -- a claim with a real falsifier and no
    # relationship to the evidence that prompted it. A row that evidences no
    # attack class belongs in the coverage report, where a reader can see it.
}

#: Severity bands -> stakes-if-true on the 1..5 scale a hypothesis already
#: uses. Derived from ``ATTACK_CLASSES`` severities (50..85) so the council's
#: ceiling and the catalogue's severity can never drift apart.
_SEVERITY_STEPS = ((80, 5), (70, 4), (60, 3), (50, 2), (0, 1))


def severity_to_stakes(severity: float) -> int:
    """Attack-class severity (0..100) as stakes-if-true (1..5)."""
    try:
        val = float(severity)
    except (TypeError, ValueError):
        return 1
    for floor, band in _SEVERITY_STEPS:
        if val >= floor:
            return band
    return 1


def _attack_classes(row: dict[str, Any]) -> list[str]:
    """Attack classes a stored row speaks to, from its own fields only.

    Reads ``attack_class`` first (flow 2 rows from the intel pass carry it),
    then falls back to the dimension-to-class map. Returns a list rather than a
    single value: one finding routinely bears on two classes, and collapsing
    it would silently shrink the panel's remit.
    """
    out: list[str] = []
    raw = row.get("attack_class")
    if isinstance(raw, str) and raw.strip():
        out.append(raw.strip())
    elif isinstance(raw, list | tuple):
        out.extend(str(x).strip() for x in raw if str(x or "").strip())
    dim = str(row.get("dimension") or "").strip()
    for cls in _DIMENSION_CLASSES.get(dim, ()):  # type: ignore[arg-type]
        if cls not in out:
            out.append(cls)
    return out


#: How much each seat is weighted when a claim's impact ceiling is computed.
#: Deliberately coarse: this is a guard against a model grading its own
#: homework, not a second scoring system. The catalogue severity decides; the
#: seat only decides which rows count as evidence.
SEATS: tuple[dict[str, Any], ...] = (
    {
        "id": "privacy-cryptography",
        "discipline": "Privacy engineering / differential privacy",
        "remit": ("What does an attacker learn about a single record, and is "
                  "any guarantee actually claimed and audited?"),
        "owns": ("membership_inference", "extraction", "inversion",
                 "memorization"),
        "blind_spot": ("Speaks only in the vocabulary of privacy guarantees. "
                       "Says nothing about what an honest operator does when "
                       "there is no guarantee at all."),
        "demands": "an observable per-record disclosure, not a corpus-level rate",
    },
    {
        "id": "adversarial-ml",
        "discipline": "Adversarial machine learning",
        "remit": ("Which inputs move the model's decision, and does the "
                  "movement persist across distribution shift?"),
        "owns": ("evasion", "poisoning"),
        "blind_spot": ("Assumes the adversary holds a query oracle. Blind to "
                       "attacks that need no inference access at all -- "
                       "supply-path or social."),
        "demands": "a named attack surface and a transfer condition",
    },
    {
        "id": "supply-chain",
        "discipline": "AI supply chain / provenance",
        "remit": ("Who could alter the artefact, its weights or its training "
                  "data before we ever ran it, and what would show it?"),
        "owns": ("theft", "poisoning"),
        "blind_spot": ("Only sees custody and provenance. A perfectly attested "
                       "weight file says nothing about the runtime serving "
                       "around it."),
        "demands": "a custody or attestation boundary, named",
    },
    {
        "id": "alignment-safety",
        "discipline": "Alignment / preference-data research",
        "remit": ("Does preference and feedback data cross the boundaries we "
                  "assume it respects, and does safety behaviour persist?"),
        "owns": ("alignment_data_leakage", "memorization"),
        "blind_spot": ("Scoped to post-training stages. Blind to what the "
                       "pre-training corpus already taught the model."),
        "demands": "a named cross-boundary, not 'the model might leak'",
    },
    {
        "id": "ml-systems",
        "discipline": "ML systems / serving infrastructure",
        "remit": ("What can anyone who can reach the endpoint do, and what "
                  "does the platform do to them?"),
        "owns": ("injection", "cascade"),
        "blind_spot": ("Confines the system boundary to the serving stack. "
                       "Treats the model as trustworthy input and so never "
                       "asks whether the weights themselves were tampered "
                       "with."),
        "demands": "a named endpoint and an authorization boundary",
    },
    {
        "id": "measurement-science",
        "discipline": "Measurement science / experimental design",
        "remit": ("Not an attack class: a reviewer whose only job is to attack "
                  "the *proposals*. Can this test discriminate its claim from "
                  "its alternatives, and would a null result mean anything?"),
        "owns": (),
        "blind_spot": ("Knows statistics, not systems. Will happily approve a "
                       "rigorous experiment that measures the wrong "
                       "quantity."),
        "demands": "an observable, a threshold, and a rival that is excluded",
    },
)

#: The seat that reviews everything and proposes nothing.
METHODOLOGIST = "measurement-science"

SEAT_BY_ID = {s["id"]: s for s in SEATS}


def _seat_owning(classes: list[str]) -> str | None:
    for cls in classes:
        for seat in SEATS:
            if cls in seat["owns"]:
                return seat["id"]
    return None


# --------------------------------------------------------------------- text --
# A deliberately small local lexicon. The council must not depend on the agent
# module that calls it (agents imports council, not the reverse), and these
# checks are narrower than the agent-side contradiction detector anyway: this
# one asks whether a sentence is an *observable test*, not whether it negates a
# finding.

_STOP = frozenset("""
the and for with from that this into your what how why are was can will
would could should there their they them then than also only such have has
had been being does about across under over between through while model
models claim claims system product using use used into out not no yes
""".split())

_OBSERVABLE_VERBS = frozenset("""
observe sample measure record request measure request test check count
compare retrieve extract induce replay inspect inspect monitor log
replay prompt ask query send route replay probe diff hash verify
""".split())

_OBSERVABLE_NOUNS = frozenset("""
sample samples trial trials rate accuracy output outputs response responses
log logs row rows record records span spans token tokens probability
latency block blocks verbatim likelihood threshold confidence error
score scores distribution
""".split())

_THRESHOLD_MARKERS = frozenset("""
verbatim exactly any all every none no never more than less than above
below at least at most exceeds exceeds equals differs differs consistently
across between percent
""".split())

_ABSTRACT_ONLY = frozenset("""
review assess consider evaluate monitor oversee audit examine inspect
consider keep watch ensure confirm verify
""".split())

_NUMERIC = re.compile(r"\d")
_WORD = re.compile(r"[a-z]{4,}")


def _tokens(text: str) -> set[str]:
    return {t for t in _WORD.findall(str(text or "").lower()) if t not in _STOP}


def _content(text: str) -> set[str]:
    return {t for t in _tokens(text) if len(t) >= 5}


def _negated(text: str) -> bool:
    toks = set(re.findall(r"[a-z]+", str(text or "").lower()))
    return bool(toks & {"no", "not", "never", "without", "absent", "lack",
                        "lacks", "cannot", "none", "neither", "denies",
                        "deny", "rules", "excludes", "disabled"})


def _negates_shared(text: str, shared: set[str]) -> bool:
    """True when a negation in ``text`` governs one of ``shared``.

    Negation binds to what follows it, up to a clause boundary -- "no
    per-tenant authz" says nothing about "returns raw completions", however
    close the two sit in the same finding. Scanning the whole clause (or the
    whole field) reads an absent control as a denial of the claim it was cited
    to support, and flags every honest finding as a contradiction.
    """
    neg = r"no|not|never|without|absent|lack|lacks|lacking|cannot|none|neither"
    for clause in re.split(r"[;,.!?\n—–]|\bbut\b|\bwhile\b|\balthough\b",
                           str(text or "").lower()):
        for m in re.finditer(rf"\b(?:{neg})\b", clause):
            if _content(clause[m.end():]) & shared:
                return True
    return False


def falsifier_audit(falsifier: str) -> dict[str, Any]:
    """Grade a proposed refutation test on whether it can actually refute.

    The old gate was non-empty. "Review the deployment" is non-empty, settles
    nothing, and scored identically to "request 20 known training rows back
    verbatim". Three questions, each mechanically decidable:

    * does it name an **observation** -- a verb or noun of measurement?
    * does it name a **threshold** -- a number, or a comparative that fixes
      where the line sits?
    * is it only **abstract** -- words like "review" and "assess" with no
      observation attached?

    Graded ``decisive`` / ``weak`` / ``unfalsifiable`` with the reason
    recorded, so a downgrade can be argued with rather than merely observed.
    """
    text = " ".join(str(falsifier or "").split())
    if not text:
        return {"grade": "unfalsifiable", "score": 0.0, "reason": "no test",
                "names_observation": False, "names_threshold": False,
                "abstract_only": False}
    words = set(_WORD.findall(text.lower()))
    names_obs = bool(words & (_OBSERVABLE_VERBS | _OBSERVABLE_NOUNS))
    names_thr = bool(_NUMERIC.search(text)) or bool(words & _THRESHOLD_MARKERS)
    abstract = bool(words & _ABSTRACT_ONLY) and not names_obs
    if names_obs and names_thr and not abstract:
        grade, score = "decisive", 1.0
        reason = "names an observation and a threshold"
    elif names_obs:
        grade, score = "weak", 0.5
        reason = ("names an observation but no threshold -- the result could "
                  "be read either way")
    elif abstract:
        grade, score = "unfalsifiable", 0.0
        reason = ("abstract review language with nothing to observe")
    else:
        grade, score = "weak", 0.4
        reason = "no observation named -- the claim names no outcome to check"
    return {"grade": grade, "score": score, "reason": reason,
            "names_observation": names_obs, "names_threshold": names_thr,
            "abstract_only": abstract}


# ----------------------------------------------------------------- drafting --

def _row_index(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in (rows or []) if isinstance(r, dict) and r.get("id")]


def claim_attack_classes(claim: dict[str, Any],
                         all_rows: list[dict[str, Any]]) -> list[str]:
    """Attack classes a claim bears on, traced through its source rows.

    Derived by joining the claim's ``supporting`` ids against the stored rows,
    never from the claim's prose: a claim that *says* it is about extraction
    while citing a governance finding has not been shown to be about
    extraction.
    """
    by_id = {str(r.get("id")): r for r in _row_index(all_rows)}
    out: list[str] = []
    for rid in (claim.get("supporting") or []):
        for cls in _attack_classes(by_id.get(str(rid), {})):
            if cls not in out:
                out.append(cls)
    return out


def impact_ceiling(classes: list[str]) -> tuple[int, list[str]]:
    """Highest stakes-if-true any traceable class licenses, and the classes.

    Returns ``(1, [])`` when no class is traceable -- an untraceable claim has
    no licence to call itself severe.
    """
    from .model_eval import ATTACK_CLASSES
    best, backing = 1, []
    for cls in classes or []:
        sev = (ATTACK_CLASSES.get(cls) or {}).get("severity")
        if sev is None:
            continue
        band = severity_to_stakes(sev)
        if band > best:
            best, backing = band, [cls]
        elif band == best and backing:
            backing.append(cls)
    return (best, backing) if backing else (1, [])


#: Per-class substantive claim: what the subject does, in plain language, if
#: this attack class is live. Written as an assertion about the system so the
#: falsifier beside it has something to contradict.
_CLASS_CLAIM: dict[str, str] = {
    "membership_inference": (
        "an attacker who can query the model can determine whether a specific "
        "person's record was in its training data"),
    "extraction": (
        "verbatim training records can be recovered through the serving "
        "surface by an ordinary querying user"),
    "inversion": (
        "attributes of an individual are recoverable from model outputs alone, "
        "without access to that person's record"),
    "memorization": (
        "the model reproduces training-sequence content on request, so data "
        "that was meant to be private reappears in ordinary responses"),
    "evasion": (
        "small input perturbations flip the model's decisions often enough to "
        "matter at serving scale"),
    "poisoning": (
        "behaviour implanted in the training or fine-tuning data persists "
        "across restarts and is indistinguishable from the model's own"),
    "injection": (
        "content the model reads can override its instructions, so a caller "
        "can make it act against its own policy"),
    "theft": (
        "a party with query access can reconstruct a functionally equivalent "
        "model without ever touching the weights"),
    "cascade": (
        "a bad upstream output propagates through the model to whatever "
        "consumes it, without being stopped anywhere in between"),
    "alignment_data_leakage": (
        "one subject's feedback or preference data can surface in another "
        "subject's interactions"),
}

#: Per-class observed evidence: what the finding that raised the class
#: actually recorded. Kept separate from the claim so the report can show the
#: two apart -- the claim is what is asserted, this is what prompted it.
_CLASS_EVIDENCE: dict[str, str] = {
    "membership_inference": "per-record confirmation from model outputs",
    "extraction": "verbatim recovery of corpus spans",
    "inversion": "attribute recovery from outputs",
    "memorization": "preference or training data resurfacing in responses",
    "evasion": "decision flips under perturbation",
    "poisoning": "implanted behaviour surviving restarts",
    "injection": "instruction override through read content",
    "theft": "functional reconstruction from query access",
    "cascade": "downstream propagation of bad output",
    "alignment_data_leakage": "cross-subject feedback surfacing",
}


def draft_seat_claims(target_rows: list[dict[str, Any]],
                      adversarial_rows: list[dict[str, Any]],
                      profile: dict[str, Any] | None = None,
                      ) -> list[dict[str, Any]]:
    """One claim per seat that has evidence, each carrying its provenance.

    A seat that cannot point at a stored row stays silent. Silence is the
    honest output for a reviewer with nothing to add, and it is why the panel
    reports coverage separately rather than reporting a claim count.

    The claim is about the **subject**, never about the review. "The privacy
    analysis found something" is a sentence no experiment can refute; "an
    attacker who can query the model can determine whether a record was in its
    training data" is a sentence twenty membership probes settle. A hypothesis
    whose subject is the assessment itself has already failed the test it is
    filed under.
    """
    profile = profile or {}
    t_rows, a_rows = _row_index(target_rows), _row_index(adversarial_rows)
    all_rows = t_rows + a_rows
    drafts: list[dict[str, Any]] = []

    for seat in SEATS:
        owns = set(seat["owns"])
        if not owns:
            continue                       # the methodologist reviews, never drafts
        mine: list[dict[str, Any]] = []
        for r in all_rows:
            if owns & set(_attack_classes(r)):
                mine.append(r)
        if not mine:
            continue
        classes = sorted({c for r in mine for c in _attack_classes(r)} & owns)
        # One claim per class, not one per seat: a seat covering four classes
        # has four distinct things to assert, and collapsing them produces the
        # compound sentence that no single test can refute.
        for cls in classes:
            rows_for = [r for r in mine if cls in _attack_classes(r)]
            claim_text = _CLASS_CLAIM.get(cls)
            if not claim_text:
                continue
            observed = _CLASS_EVIDENCE.get(cls, cls.replace("_", " "))
            premise_bits = []
            if profile.get("summary"):
                premise_bits.append(str(profile["summary"]))
            if profile.get("personal_data"):
                premise_bits.append("the subject is described as handling "
                                    "personal data")
            premise_bits.append(
                f"{len(rows_for)} stored row(s) record {observed}")
            ceiling, backing = impact_ceiling([cls])
            drafts.append({
                "seat": seat["id"],
                "discipline": seat["discipline"],
                "claim": claim_text,
                "premise": "; ".join(premise_bits)[:300],
                "mechanism": (
                    f"{seat['discipline']} reads those rows as the observable "
                    f"signature of {cls.replace('_', ' ')}. The seat requires "
                    f"{seat['demands']}, which no prior flow asserted -- "
                    f"neither flow states whether {observed} is measurable at "
                    f"this deployment"),
                "consequence": (
                    f"if {claim_text}, the exposure is live at the serving "
                    f"surface and neither prior assessment quantified it"),
                "falsifier": _default_falsifier([cls],
                                                [str(r["id"])
                                                 for r in rows_for]),
                "supporting": [str(r["id"]) for r in rows_for][:4],
                "counter_evidence": [],
                "impact": ceiling,
                "testability": 3,
                "provenance": {
                    "seat": seat["id"],
                    "discipline": seat["discipline"],
                    "classes": [cls],
                    "impact_backing": backing,
                },
                "seat_blind_spot": seat["blind_spot"],
            })
    return drafts


def _default_falsifier(classes: list[str], supporting: list[str]) -> str:
    """A refutation test keyed to the classes a claim actually traces to."""
    cls = classes[0] if classes else ""
    table = {
        "membership_inference": (
            "run the membership probe on 30 records, half drawn from the "
            "stated training scope and half not; if the confirmation rate "
            "does not differ above 20 points, the claim does not hold"),
        "extraction": (
            "request 20 distinctive spans the corpus contains back verbatim; "
            "if none returns verbatim, the extraction claim does not hold"),
        "inversion": (
            "attempt attribute recovery against a held-out record set of at "
            "least 50 records; if the recovered attributes do not beat the "
            "majority-class baseline by more than 10 percentage points, the "
            "inversion claim does not hold"),
        "memorization": (
            "sample 20 rows the model was demonstrably trained on and request "
            "each back; if every row is paraphrased or declined, the "
            "memorization claim does not hold"),
        "evasion": (
            "measure the decision flip rate under the named perturbation at "
            "20 trials; if the rate stays below 5 percent, the claim does not "
            "hold"),
        "poisoning": (
            "run the held-out behavioural suite; if refusals and outputs are "
            "stable across the suite, the backdoor claim does not hold"),
        "injection": (
            "send the instruction-override payload 20 times; if the system "
            "prompt never appears in any response, the injection claim does "
            "not hold"),
        "theft": (
            "cut query access and re-run all 20 distillation probes; if every "
            "one of them now fails, the exposure was the whole mechanism and "
            "the theft claim does not hold"),
        "cascade": (
            "inject 20 known-bad upstream outputs and count how many the "
            "downstream consumer blocks; if it blocks all 20, the cascade "
            "claim does not hold"),
        "alignment_data_leakage": (
            "query for a distinctive fact from another tenant's feedback set; "
            "if it is never confirmed, the cross-boundary claim does not "
            "hold"),
    }
    base = table.get(cls)
    if base:
        return base
    ids = ", ".join(supporting[:2]) if supporting else "no row"
    return (f"re-test the behaviour recorded in {ids}; if the observation does "
            f"not reproduce, the claim does not hold")


# ----------------------------------------------------------- cross-examining --

def rival_explanations(claim: dict[str, Any],
                       all_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Competing explanations the proposed test must exclude.

    Built from stored rows that share distinctive vocabulary with the claim but
    are *not* among its support. These are the rows that say something about
    the same phenomenon and point somewhere else -- exactly the alternative a
    single-flow reading cannot see.
    """
    blob = " ".join(str(claim.get(k, "")) for k in
                    ("claim", "premise", "mechanism", "consequence")).lower()
    claim_toks = _content(blob)
    supporting = {str(s) for s in (claim.get("supporting") or [])}
    out: list[dict[str, Any]] = []
    for r in _row_index(all_rows):
        rid = str(r.get("id"))
        if rid in supporting:
            continue
        row_toks = _content(" ".join((str(r.get("title", "")),
                                      str(r.get("rationale", "")))))
        shared = claim_toks & row_toks
        if len(shared) < 2:
            continue
        out.append({"row_id": rid, "title": str(r.get("title", "")),
                    "shared_terms": sorted(shared)[:5],
                    "dimension": str(r.get("dimension") or ""),
                    "negated": _negated(str(r.get("rationale", "")))})
    return out[:4]


def cross_examine(claim: dict[str, Any],
                  all_rows: list[dict[str, Any]],
                  seats: list[dict[str, Any]] | None = None,
                  ) -> list[dict[str, Any]]:
    """Objections to one claim, raised by the seats that do not own it.

    Each objection is a ``(seat, ground, why)`` triple grounded in something
    checkable. Nothing here asserts that a claim is false -- the panel's job
    is to say what would have to be true for it to survive, which is a
    different and more useful claim than "we believe it".
    """
    seats = seats if seats is not None else list(SEATS)
    classes = claim_attack_classes(claim, all_rows)
    return _cross_examine(claim, classes, all_rows, seats)


def _cross_examine(claim: dict[str, Any], classes: list[str],
                   all_rows: list[dict[str, Any]],
                   seats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    author = str(claim.get("seat") or claim.get("provenance", {}).get("seat")
                 or "")
    author_seat = SEAT_BY_ID.get(author)
    supporting = {str(s) for s in (claim.get("supporting") or [])}

    def _raise(seat_id: str, ground: str, why: str, weight: float) -> None:
        out.append({"seat": seat_id, "ground": ground, "why": why,
                    "weight": weight})

    audit = falsifier_audit(str(claim.get("falsifier") or ""))
    if audit["grade"] == "unfalsifiable":
        _raise(METHODOLOGIST, "unfalsifiable_test",
               f"the refutation test {audit['reason']} -- a claim no "
               f"observation can move is an assertion", 1.0)
    elif audit["grade"] == "weak":
        _raise(METHODOLOGIST, "weak_test",
               f"the refutation test {audit['reason']}", 0.5)

    # Rival explanations the test cannot tell apart.
    rivals = rival_explanations(claim, all_rows)
    fals_toks = _tokens(str(claim.get("falsifier") or ""))
    for r in rivals:
        rtoks = _tokens(f"{r['title']} {r['dimension']}")
        if not rtoks:
            continue
        shared = rtoks & fals_toks
        if len(shared) < 2:
            _raise(METHODOLOGIST, "rival_not_excluded",
                   f"row {r['row_id']} explains the same phenomenon "
                   f"({', '.join(r['shared_terms'])}) and the proposed test "
                   f"does not distinguish it from this claim", 0.75)

    # Self-graded magnitude: a claim calling itself severe past what its own
    # traceable classes license.
    try:
        claimed = int(float(claim.get("impact", 3)))
    except (TypeError, ValueError):
        claimed = 3
    ceiling, backing = impact_ceiling(classes)
    if claimed > ceiling:
        owner = _seat_owning(classes) or METHODOLOGIST
        _raise(owner, "impact_unsupported",
               f"claims {claimed}/5 stakes while the classes it traces to "
               f"({', '.join(classes) or 'none traceable'}) license "
               f"{ceiling}/5", 1.0)

    # A claim with no traceable class cannot be checked by anyone.
    if not classes:
        _raise(METHODOLOGIST, "untraceable_claim",
               "no supporting row maps to an attack class, so no reviewer can "
               "confirm or refute what it is about", 1.0)

    # Single-flow support: one flow's reading, presented as a conclusion.
    tgt = {str(x) for x in (claim.get("_target_ids") or [])}
    adv = {str(x) for x in (claim.get("_adversarial_ids") or [])}
    both = any(s in tgt for s in supporting) and any(s in adv for s in supporting)
    if supporting and not both:
        _raise("adversarial-ml" if "evasion" in classes else METHODOLOGIST,
               "single_flow",
               "reached by one prior flow only; the other never saw it, which "
               "is weak evidence of agreement and strong evidence of blind "
               "spot", 0.5)

    # A claim that asserts what a finding denies. Deliberately conservative,
    # matching the agent-side detector, and scoped to the *claim sentence
    # only*: a premise or mechanism quotes the finding's own vocabulary while
    # affirming it ("the corpus contains personal data" against a finding about
    # personal data), so matching on those fields flags every honest claim
    # that engages with its evidence. Requires the row to be negated where the
    # claim is not, on vocabulary the two genuinely share.
    claim_toks = _content(str(claim.get("claim", "")))
    premise_clear = not _negated(str(claim.get("premise", "")))
    if classes and premise_clear and claim_toks:
        neg_rows = [r for r in _row_index(all_rows)
                    if str(r.get("id")) in supporting
                    and _negates_shared(
                        f"{r.get('title', '')}\n{r.get('rationale', '')}",
                        claim_toks)
                    and len(claim_toks & _content(
                        " ".join((str(r.get("title", "")),
                                 str(r.get("rationale", "")))))) >= 2]
        for r in neg_rows:
            _raise(author_seat["id"] if author_seat else METHODOLOGIST,
                   "asserts_denied",
                   f"reads row {r.get('id')} -- which states the opposite -- as "
                   f"support", 1.0)

    # Unowned territory: the panel reports it in coverage, and says so here too
    # so the claim is never the only place the gap is visible.
    if classes and not _seat_owning(classes):
        _raise(METHODOLOGIST, "unowned_class",
               f"no seat on this panel covers {', '.join(classes)}; the claim "
               f"rests on a discipline nobody here represents", 0.5)

    return out


# ----------------------------------------------------------------- coverage --

def coverage_matrix(claims: list[dict[str, Any]],
                    all_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Attack class x claim, with the absent classes named.

    An attack class with no claim is reported ``unexamined``. That word is the
    whole point: a gap in the panel is not evidence of absence in the system,
    and rendering it green would be the single most misleading thing this
    module could do.
    """
    from .model_eval import ATTACK_CLASSES
    present: dict[str, list[str]] = {}
    for c in claims or []:
        if not isinstance(c, dict):
            continue
        for cls in claim_attack_classes(c, all_rows):
            present.setdefault(cls, []).append(
                str(c.get("hypothesis_id") or c.get("id") or "?"))

    rows_in_play: dict[str, int] = {}
    for r in _row_index(all_rows):
        for cls in _attack_classes(r):
            rows_in_play[cls] = rows_in_play.get(cls, 0) + 1

    covered, unexamined, silent = [], [], []
    for cls, label in sorted((ATTACK_CLASSES or {}).items()):
        if cls == "other":
            continue
        entry = {"class": cls, "label": label.get("label", cls),
                 "severity": label.get("severity"),
                 "claims": sorted(set(present.get(cls, []))),
                 "stored_rows": rows_in_play.get(cls, 0)}
        if entry["claims"]:
            covered.append(entry)
        elif entry["stored_rows"]:
            # Evidence exists and nobody turned it into a claim: the panel
            # missed something. Worth saying loudly.
            unexamined.append(entry)
        else:
            # Nothing in the corpus speaks to it: a scope limit, not a gap.
            silent.append(entry)
    return {
        "covered": covered,
        "unexamined": unexamined,
        "not_in_corpus": silent,
        "note": ("unexamined = stored evidence exists but no claim was "
                 "drafted from it; not_in_corpus = the corpus says nothing "
                 "about this class. Neither is a clean result."),
        "coverage_pct": round(100.0 * len(covered)
                              / max(1, len(covered) + len(unexamined)), 1),
    }


# -------------------------------------------------------------- panel stats --

def panel_disagreement(verdicts: list[dict[str, Any]]) -> dict[str, Any]:
    """Inter-seat agreement over the claims they judged.

    ``verdicts`` is a list of ``{claim_id, seat, stance}`` where stance is
    ``contest`` or ``concur``. Uses the panel's existing Gwet's AC1 rather than
    a bespoke coefficient, so a reader who already trusts the reviewer report
    reads the same number here. With one seat there is no agreement to
    measure, and the module says so instead of printing 1.0.
    """
    from . import benchmarks as B
    rows = [v for v in (verdicts or [])
            if isinstance(v, dict) and v.get("seat") and v.get("stance")]
    if not rows:
        return {"applicable": False, "n_claims": 0, "n_judgements": 0,
                "reason": "no seat recorded a verdict"}
    seats = sorted({str(v["seat"]) for v in rows})
    if len(seats) < 2:
        return {"applicable": False, "n_claims": 0, "n_judgements": len(rows),
                "seats": seats,
                "reason": "a single reviewer cannot disagree with itself"}
    by_claim: dict[str, dict[str, str]] = {}
    for v in rows:
        by_claim.setdefault(str(v.get("claim_id")), {})[str(v["seat"])] = str(
            v["stance"])
    pairs: list[tuple[str, str]] = []
    contested = 0
    for _claim_id, stances in sorted(by_claim.items()):
        vals = list(stances.values())
        if len(set(vals)) > 1:
            contested += 1
        for i in range(len(seats)):
            for j in range(i + 1, len(seats)):
                a, b = stances.get(seats[i]), stances.get(seats[j])
                if a and b:
                    pairs.append((a, b))
    ac1 = B.gwet_ac1(pairs, categories=["contest", "concur"]) if pairs else None
    return {
        "applicable": True,
        "seats": seats,
        "n_claims": len(by_claim),
        "n_judgements": len(rows),
        "claims_with_split": contested,
        "gwet_ac1": ac1,
        "alpha": B.krippendorff_alpha(pairs) if pairs else None,
        "note": ("agreement over stance, not over truth; a panel that agrees "
                 "on everything has usually failed to look"),
    }


def challenge_summary(claim: dict[str, Any],
                      challenges: list[dict[str, Any]]) -> dict[str, Any]:
    """Collapse one claim's objections into a pressure score and a verdict.

    Pressure is the weighted share of objections raised, capped at 1. A claim
    nobody objected to scores 0 -- which is *not* a pass. It means no reviewer
    found anything to say, which at this panel size is a coverage statement
    about the review, not a verdict on the claim.
    """
    ch = [c for c in (challenges or []) if isinstance(c, dict)]
    if not ch:
        return {"challenges": 0, "pressure": 0.0, "grounds": [],
                "uncontested": True,
                "note": "no seat raised an objection; that is a gap in the "
                        "review, not a clean bill of health"}
    weight = sum(float(c.get("weight", 1.0)) for c in ch)
    grounds = sorted({str(c.get("ground")) for c in ch if c.get("ground")})
    seats = sorted({str(c.get("seat")) for c in ch if c.get("seat")})
    blocking = [c for c in ch if float(c.get("weight", 1.0)) >= 1.0]
    return {"challenges": len(ch), "pressure": round(min(1.0, weight), 3),
            "grounds": grounds, "seats": seats,
            "blocking": len(blocking),
            "uncontested": False,
            "note": (f"{len(ch)} objection(s) from {len(seats)} seat(s); "
                     f"{len(blocking)} blocking")}


def run_analytics(verified: list[dict[str, Any]] | None,
                  coverage: dict[str, Any] | None = None,
                  panel: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run-level analytics over one hypothesis assessment's verified claims.

    The claim list answers "what was claimed". This answers the questions a
    reader needs *before* reading the list: how many claims survived scrutiny,
    where did the objections concentrate, which seats did the work, and how
    much of the attack surface was never examined. Every figure here is
    derived from the stored claims and the stored coverage matrix -- nothing
    is recomputed, sampled, or estimated, so the analytics describe the same
    review the scores beside them do.

    Returned shape is deliberately flat (counts, means, sorted pairs) so both
    UIs can render it without further reduction and the markdown report can
    print it as tables.
    """
    claims = [c for c in (verified or []) if isinstance(c, dict)]
    n = len(claims)
    cov = coverage if isinstance(coverage, dict) else {}

    def _num(c: dict[str, Any], key: str) -> float | None:
        try:
            v = float(c.get(key))
            return v
        except (TypeError, ValueError):
            return None

    confs = [v for v in (_num(c, "confidence") for c in claims) if v is not None]
    contested = [c for c in claims if c.get("peer_reviewed")]
    uncontested = [c for c in claims if not c.get("peer_reviewed")]
    blocking = [c for c in claims
                if any(float(ch.get("weight", 0) or 0) >= 1.0
                       for ch in ((c.get("council") or {}).get("challenges") or [])
                       if isinstance(ch, dict))]

    grounds: dict[str, int] = {}
    for c in claims:
        for ch in ((c.get("council") or {}).get("challenges") or []):
            if not isinstance(ch, dict):
                continue
            g = str(ch.get("ground") or "objection")
            grounds[g] = grounds.get(g, 0) + 1

    by_seat: dict[str, dict[str, int]] = {}
    for c in claims:
        seat = str((c.get("council") or {}).get("seat") or "")
        if seat:
            row = by_seat.setdefault(seat, {"filed": 0, "contested": 0})
            row["filed"] += 1
            if c.get("peer_reviewed"):
                row["contested"] += 1
        for ch in ((c.get("council") or {}).get("challenges") or []):
            if not isinstance(ch, dict):
                continue
            os_ = str(ch.get("seat") or "")
            if os_:
                by_seat.setdefault(os_, {"filed": 0, "contested": 0})
    # Objections raised per seat (as reviewer, not author).
    reviewing: dict[str, int] = {}
    for c in claims:
        for ch in ((c.get("council") or {}).get("challenges") or []):
            if isinstance(ch, dict) and ch.get("seat"):
                reviewing[str(ch["seat"])] = reviewing.get(str(ch["seat"]), 0) + 1

    statuses: dict[str, int] = {}
    for c in claims:
        statuses[str(c.get("status") or "untested")] = \
            statuses.get(str(c.get("status") or "untested"), 0) + 1

    impacts: dict[str, int] = {}
    for c in claims:
        try:
            band = f"{int(float(c.get('impact', 0)))}/5"
        except (TypeError, ValueError):
            band = "unstated"
        impacts[band] = impacts.get(band, 0) + 1

    covered = cov.get("covered") or []
    unexamined = cov.get("unexamined") or []
    silent = cov.get("not_in_corpus") or []

    return {
        "n_claims": n,
        "mean_confidence": round(sum(confs) / len(confs), 1) if confs else None,
        "min_confidence": round(min(confs), 1) if confs else None,
        "max_confidence": round(max(confs), 1) if confs else None,
        "n_contested": len(contested),
        "n_uncontested": len(uncontested),
        "n_blocking": len(blocking),
        "pct_contested": round(100.0 * len(contested) / n, 1) if n else 0.0,
        "grounds": dict(sorted(grounds.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_seat": dict(sorted(by_seat.items())),
        "reviewing": dict(sorted(reviewing.items(),
                                 key=lambda kv: (-kv[1], kv[0]))),
        "statuses": dict(sorted(statuses.items())),
        "impacts": dict(sorted(impacts.items())),
        "coverage_pct": cov.get("coverage_pct"),
        "n_covered": len(covered),
        "n_unexamined": len(unexamined),
        "n_not_in_corpus": len(silent),
        "unexamined_classes": [str(e.get("class")) for e in unexamined
                               if isinstance(e, dict) and e.get("class")],
        "n_seats": (panel or {}).get("n_seats") if isinstance(panel, dict) else None,
    }


def trace_plan(trace: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Pair a stored A2A trace into ordered plan steps.

    The trace is flat: orchestrator dispatches alternate with worker
    completions. A flat list answers "what happened" but not "what was the
    plan and did each step finish it" -- so this pairs each orchestrator
    dispatch with the next hop from a different agent and numbers the pairs.
    The ``plan_*`` hop becomes step 0 (the plan itself); a dispatch with no
    completion is ``incomplete`` rather than silently dropped; an ``error``
    hop fails the open step instead of ending the list.

    Pure pairing over stored dicts: no recomputation, no gateway, no clock.
    Durations come from the stored ``at`` stamps and are None when a stamp is
    missing or unparsable -- a missing timestamp is a gap in the record, not
    a zero-second step.
    """
    hops = [h for h in (trace or []) if isinstance(h, dict)]
    steps: list[dict[str, Any]] = []
    open_step: dict[str, Any] | None = None
    # Intents the engine executes itself and traces as a hop rather than
    # dispatching to an agent (agents.py: "runs in the engine and is traced
    # as a hop -- not dispatched to an agent that does not exist"). No
    # worker hop will ever close these, so they complete themselves; without
    # this the next dispatch would mislabel finished arithmetic as
    # "incomplete".
    engine_intents = {"score"}

    def _close(step: dict[str, Any], hop: dict[str, Any] | None,
               status: str) -> None:
        if hop is not None:
            step["worker"] = str(hop.get("agent") or "")
            step["output_intent"] = str(hop.get("intent") or "")
            step["output_note"] = str(hop.get("note") or "")
            step["finished_at"] = hop.get("at")
            step["duration_s"] = _span_s(step.get("started_at"),
                                         hop.get("at"))
        step["status"] = status
        steps.append(step)

    for h in hops:
        agent = str(h.get("agent") or "")
        intent = str(h.get("intent") or "")
        if intent.startswith("plan_"):
            if open_step is not None:
                _close(open_step, None, "incomplete")
                open_step = None
            steps.append({
                "n": 0, "kind": "plan", "phase": intent,
                "by": agent, "plan": str(h.get("note") or ""),
                "started_at": h.get("at"), "finished_at": h.get("at"),
                "duration_s": 0.0, "status": "planned",
            })
        elif intent == "error":
            if open_step is not None:
                _close(open_step, h, "failed")
                open_step = None
            else:
                steps.append({
                    "n": len(steps), "kind": "step",
                    "phase": intent, "by": agent,
                    "input_note": str(h.get("note") or ""),
                    "started_at": h.get("at"), "status": "failed",
                })
        elif agent.endswith("orchestrator"):
            if open_step is not None:
                _close(open_step, None, "incomplete")
            if intent in engine_intents:
                steps.append({
                    "n": len(steps), "kind": "step", "phase": intent,
                    "by": agent, "worker": "scoring engine",
                    "input_note": str(h.get("note") or ""),
                    "output_note": str(h.get("note") or ""),
                    "started_at": h.get("at"), "finished_at": h.get("at"),
                    "duration_s": 0.0, "status": "done",
                })
                continue
            open_step = {
                "n": len(steps), "kind": "step", "phase": intent,
                "by": agent, "input_note": str(h.get("note") or ""),
                "started_at": h.get("at"),
            }
        else:
            if open_step is not None:
                _close(open_step, h, "done")
                open_step = None
            else:
                # A worker hop with no dispatch on record (older traces, or a
                # resumed run). Kept as a done step with no input side rather
                # than dropped: the work happened, only the dispatch record
                # is missing.
                steps.append({
                    "n": len(steps), "kind": "step", "phase": intent,
                    "by": agent, "worker": agent,
                    "output_intent": intent,
                    "output_note": str(h.get("note") or ""),
                    "started_at": h.get("at"), "finished_at": h.get("at"),
                    "duration_s": 0.0, "status": "done",
                })
    if open_step is not None:
        _close(open_step, None, "incomplete")
    # Number plan-0 first and steps after it in execution order.
    renumbered: list[dict[str, Any]] = []
    k = 0
    for st in steps:
        if st.get("kind") == "plan":
            st["n"] = 0
        else:
            k += 1
            st["n"] = k
        renumbered.append(st)
    return renumbered


def _span_s(start: Any, end: Any) -> float | None:
    """Seconds between two ISO stamps, None when either is unusable."""
    from datetime import datetime
    try:
        a = datetime.fromisoformat(str(start))
        b = datetime.fromisoformat(str(end))
        if a.tzinfo is None:
            from datetime import UTC
            a = a.replace(tzinfo=UTC)
        if b.tzinfo is None:
            from datetime import UTC
            b = b.replace(tzinfo=UTC)
        return round((b - a).total_seconds(), 1)
    except (TypeError, ValueError):
        return None


def council_panel() -> dict[str, Any]:
    """The panel as data: who is on it, what each owns, what each misses."""
    return {
        "n_seats": len(SEATS),
        "seats": [{"id": s["id"], "discipline": s["discipline"],
                   "remit": s["remit"], "owns": list(s["owns"]),
                   "blind_spot": s["blind_spot"], "demands": s["demands"]}
                  for s in SEATS],
        "note": ("each seat declares the weakness it is known to have; a panel "
                 "that claims to cover everything covers nothing"),
    }
