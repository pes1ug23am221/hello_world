"""Turn scored findings into a release decision.

Four verdicts, because three are not enough:

``PASS``
    The analysis ran, and nothing it can see crosses a threshold.
``FLAG``
    Something needs a human before the release ships.
``BLOCK``
    Something crosses the blocking threshold on evidence good enough to act on.
``INCONCLUSIVE``
    The analysis could not answer the question. This is the verdict that justifies
    the module: a tool with only PASS/FLAG/BLOCK has to map "no entry point was
    configured" onto PASS, and then a release with no TARA config looks exactly like
    a clean one. `INCONCLUSIVE` is never PASS, and no acceptance can waive it.

Two policies are deliberately not the tool's decision to make:

* **Whether a guessed finding may block.** Refusing a release because a component's
  short name contains "brake", with no hazard analysis behind it, is not defensible,
  and a gate that does it gets switched off inside a month. So by default an
  assumed-input finding that would have blocked is downgraded to FLAG — and the
  downgrade is reported, not hidden. A programme with a real TARA sets
  `block_on_assumed=True` and gets the stricter behaviour.
* **What an inconclusive run costs.** The verdict is stated honestly either way; the
  policy chooses whether CI treats it as fatal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import findings as findings_mod
from . import severity as severity_mod

PASS = "PASS"
FLAG = "FLAG"
BLOCK = "BLOCK"
INCONCLUSIVE = "INCONCLUSIVE"

#: Worst first. `BLOCK` outranks `INCONCLUSIVE` because a confirmed blocking finding
#: is actionable whether or not the rest of the analysis completed.
PRECEDENCE = (BLOCK, INCONCLUSIVE, FLAG, PASS)

EXIT_CODES = {PASS: 0, FLAG: 1, INCONCLUSIVE: 2, BLOCK: 3}

#: Categories no acceptance can suppress. Waiving "we did not run the analysis" is
#: how a gate stops meaning anything.
UNWAIVABLE = frozenset({findings_mod.NOT_ANALYSED})


@dataclass(frozen=True)
class Policy:
    """Thresholds and waivers for one programme."""

    block_at: int = 5
    flag_at: int = 3
    #: Whether a finding built on heuristic seeds may block a release.
    block_on_assumed: bool = False
    #: Whether an unanswerable analysis is escalated to BLOCK.
    inconclusive_blocks: bool = False
    #: Finding ids a team has reviewed and accepted.
    accepted: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.flag_at > self.block_at:
            raise ValueError(
                f"flag_at ({self.flag_at}) is above block_at ({self.block_at}), which "
                f"would make every blocking finding invisible to triage"
            )

    @classmethod
    def from_dict(cls, data: dict) -> Policy:
        data = data or {}
        return cls(
            block_at=int(data.get("block_at", 5)),
            flag_at=int(data.get("flag_at", 3)),
            block_on_assumed=bool(data.get("block_on_assumed", False)),
            inconclusive_blocks=bool(data.get("inconclusive_blocks", False)),
            accepted=frozenset(data.get("accepted") or ()),
        )


def load_policy(path: str | Path) -> Policy:
    """Load a policy from YAML::

        block_at: 5
        flag_at: 3
        block_on_assumed: false
        accepted:
          - "rehosted-component:/V/Swc/Veh/abs"
    """
    import yaml

    return Policy.from_dict(yaml.safe_load(Path(path).read_text()) or {})


@dataclass(frozen=True)
class Decision:
    """The verdict, and everything needed to argue with it."""

    verdict: str
    policy: Policy = field(default_factory=Policy)
    #: Findings that counted towards the verdict, worst first.
    considered: tuple[severity_mod.Scored, ...] = ()
    #: Suppressed by an acceptance in the policy.
    accepted: tuple[severity_mod.Scored, ...] = ()
    #: Reported but never able to affect the verdict.
    informational: tuple[severity_mod.Scored, ...] = ()
    #: Would have blocked, but its inputs were guessed.
    downgraded: tuple[severity_mod.Scored, ...] = ()
    #: Acceptances that matched nothing in this run — most likely stale waivers.
    stale_acceptances: tuple[str, ...] = ()
    #: Acceptances the policy was not allowed to honour.
    refused_acceptances: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return self.verdict == PASS

    @property
    def exit_code(self) -> int:
        if self.verdict == INCONCLUSIVE and self.policy.inconclusive_blocks:
            return EXIT_CODES[BLOCK]
        return EXIT_CODES[self.verdict]

    @property
    def blocking(self) -> tuple[severity_mod.Scored, ...]:
        return tuple(s for s in self.considered if self._blocks(s))

    @property
    def flagged(self) -> tuple[severity_mod.Scored, ...]:
        return tuple(
            s
            for s in self.considered
            if not self._blocks(s) and s.risk >= self.policy.flag_at
        )

    @property
    def unanalysed(self) -> tuple[severity_mod.Scored, ...]:
        return tuple(
            s for s in self.considered if s.finding.category == findings_mod.NOT_ANALYSED
        )

    @property
    def worst(self) -> severity_mod.Scored | None:
        return self.considered[0] if self.considered else None

    def _blocks(self, scored: severity_mod.Scored) -> bool:
        if scored.risk < self.policy.block_at:
            return False
        return self.policy.block_on_assumed or not scored.score.assumed

    def summary(self) -> dict[str, int | str]:
        return {
            "verdict": self.verdict,
            "exit_code": self.exit_code,
            "blocking": len(self.blocking),
            "flagged": len(self.flagged),
            "unanalysed": len(self.unanalysed),
            "downgraded": len(self.downgraded),
            "informational": len(self.informational),
            "accepted": len(self.accepted),
        }

    def __str__(self) -> str:
        head = f"{self.verdict}"
        if self.reasons:
            head += ": " + "; ".join(self.reasons)
        return head


def evaluate(
    scored: tuple[severity_mod.Scored, ...], policy: Policy | None = None
) -> Decision:
    """Apply a policy to scored findings.

    Order of operations matters. Acceptances are applied first, so a waived finding
    cannot contribute to the verdict; then informational findings are set aside, so a
    rehost can never fail a build on its own; only then are thresholds applied.
    """
    policy = policy or Policy()

    accepted: list[severity_mod.Scored] = []
    informational: list[severity_mod.Scored] = []
    considered: list[severity_mod.Scored] = []
    refused: list[str] = []
    matched: set[str] = set()

    for item in scored:
        finding = item.finding
        if finding.id in policy.accepted:
            matched.add(finding.id)
            if finding.category in UNWAIVABLE:
                refused.append(finding.id)
            else:
                accepted.append(item)
                continue
        if finding.informational:
            informational.append(item)
            continue
        considered.append(item)

    considered.sort(key=lambda s: (-s.risk, s.finding.category, s.finding.subject))

    reasons: list[str] = []
    downgraded = tuple(
        s
        for s in considered
        if s.risk >= policy.block_at and s.score.assumed and not policy.block_on_assumed
    )
    blocking = tuple(
        s
        for s in considered
        if s.risk >= policy.block_at and (policy.block_on_assumed or not s.score.assumed)
    )
    unanalysed = tuple(
        s for s in considered if s.finding.category == findings_mod.NOT_ANALYSED
    )
    # Identity, not equality: two distinct findings can compare equal once evidence is
    # excluded from the comparison, and one of them must not silence the other.
    blocking_ids = {id(s) for s in blocking}
    flagged = tuple(
        s for s in considered if id(s) not in blocking_ids and s.risk >= policy.flag_at
    )

    if blocking:
        verdict = BLOCK
        reasons.append(
            f"{len(blocking)} finding(s) at risk {policy.block_at} or above, "
            f"worst: {blocking[0].finding.title}"
        )
    elif unanalysed:
        verdict = INCONCLUSIVE
        reasons.append(
            f"{len(unanalysed)} part(s) of the analysis did not run, so no clean "
            f"result can be claimed"
        )
    elif flagged:
        verdict = FLAG
        reasons.append(
            f"{len(flagged)} finding(s) at risk {policy.flag_at} or above, "
            f"worst: {flagged[0].finding.title}"
        )
    else:
        verdict = PASS
        reasons.append("no finding reached the flag threshold")

    for item in downgraded:
        reasons.append(
            f"{item.finding.id} scored {item.risk} but its inputs were guessed, so it "
            f"flags instead of blocking (set block_on_assumed to change this)"
        )
    for finding_id in sorted(refused):
        reasons.append(f"acceptance of {finding_id} refused: this category cannot be waived")

    stale = tuple(sorted(policy.accepted - matched))
    for finding_id in stale:
        reasons.append(f"accepted {finding_id} is no longer present in this release")

    return Decision(
        verdict=verdict,
        policy=policy,
        considered=tuple(considered),
        accepted=tuple(accepted),
        informational=tuple(informational),
        downgraded=downgraded,
        stale_acceptances=stale,
        refused_acceptances=tuple(sorted(refused)),
        reasons=tuple(reasons),
    )
