#!/usr/bin/env python3
"""
search_security_rules.py

Search Panorama Security policy rules that reference one or more objects
(addresses, URL categories, source users, applications, services, …)

Multiple object names can be supplied at once; a rule matches if it
contains ANY of the provided names (OR semantics), and the match result
records which names were found.

Usage:
    python search_security_rules.py \
        --host panorama.example.com \
        --username admin \
        --password secret \
        --object-type source-user \
        --object-name 'CORP\\jdoe' 'CORP\\asmith' 'CORP\\bwayne'

Dependencies:
    pan-os-python (pip install pan-os-python)
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from panos.panorama import Panorama
from panos.policies import (
    PreRulebase,
    PostRulebase,
    DeviceGroup,
    SecurityRule,
)

logger = logging.getLogger("rule-searcher")

@dataclass
class RuleMatch:
    """A single security rule that matched the search criteria."""
    scope: str
    rule_name: str
    # Which of the searched object names were found, and in which attribute.
    matched: Dict[str, List[str]] = field(default_factory=dict)
    source: List[str] = field(default_factory=list)
    destination: List[str] = field(default_factory=list)
    category: List[str] = field(default_factory=list)
    source_user: List[str] = field(default_factory=list)
    application: List[str] = field(default_factory=list)
    service: List[str] = field(default_factory=list)
    action: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)

class PanoramaRuleSearcher:
    """
    Search Security policy rules on Panorama (pre-rulebase, post-rulebase,
    and every device-group rulebase) for one or more referenced objects.
    """

    # Maps the user-facing object type to one or more SecurityRule attributes.
    OBJECT_TYPE_MAP: Dict[str, List[str]] = {
        "address": ["source", "destination"],
        "source-address": ["source"],
        "destination-address": ["destination"],
        "url-category": ["category"],
        "source-user": ["source_user"],
        "application": ["application"],
        "service": ["service"],
    }

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        api_version: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.api_version = api_version
        self.verify_ssl = verify_ssl
        self._pano: Optional[Panorama] = None

    # -- Connection ---------------------------------------------------------
    def connect(self) -> Panorama:
        """Create and return a connected Panorama object."""
        logger.debug("Connecting to Panorama at %s", self.hostname)
        self._pano = Panorama(
            hostname=self.hostname,
            api_username=self.username,
            api_password=self.password,
        )

        self._pano.refresh_system_info()
        logger.info("Connected to Panorama %s", self.hostname)
        return self._pano

    @property
    def panorama(self) -> Panorama:
        if self._pano is None:
            raise RuntimeError("Not connected. Call connect() first.")
        return self._pano

    # -- Rule enumeration ---------------------------------------------------
    def iter_security_rules(self) -> Iterable[Tuple[str, SecurityRule]]:
        """
        Yield (scope_description, SecurityRule) for every security rule
        on Panorama.
        """
        pano = self.panorama

        for scope, rulebase_cls in (
            ("Panorama pre-rulebase", PreRulebase),
            ("Panorama post-rulebase", PostRulebase),
        ):
            rulebase = pano.add(rulebase_cls())
            for rule in SecurityRule.refreshall(rulebase):
                yield scope, rule

        for dg in DeviceGroup.refreshall(pano):
            pano.add(dg)
            for label, rulebase_cls in (
                ("pre-rulebase", PreRulebase),
                ("post-rulebase", PostRulebase),
            ):
                rulebase = dg.add(rulebase_cls())
                scope = f"DG '{dg.name}' {label}"
                for rule in SecurityRule.refreshall(rulebase):
                    yield scope, rule

    # -- Matching -----------------------------------------------------------
    @staticmethod
    def _as_list(value) -> List[str]:
        """Normalise a rule attribute (str or list) to a list of strings."""
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return list(value)

    def _rule_matches(
        self,
        rule: SecurityRule,
        attributes: Sequence[str],
        object_names: Sequence[str],
    ) -> Dict[str, List[str]]:
        """
        Return a dict describing which object names were found, keyed by the
        rule attribute in which they appear.

        Example:
            {"source_user": ["CORP\\jdoe", "CORP\\asmith"]}

        An empty dict means no match.
        """
        hits: Dict[str, List[str]] = {}
        wanted = set(object_names)

        for attr in attributes:
            members = self._as_list(getattr(rule, attr, None))
            found_here = [name for name in members if name in wanted]
            if found_here:
                hits[attr] = found_here
        return hits

    def search(
        self,
        object_type: str,
        object_names: Sequence[str],
    ) -> List[RuleMatch]:
        """
        Search all security rules for the given object references.

        :param object_type: One of OBJECT_TYPE_MAP keys.
        :param object_names: One or more names to search for (OR semantics).
        :returns: List of RuleMatch objects.
        """
        attributes = self.OBJECT_TYPE_MAP.get(object_type)
        if not attributes:
            raise ValueError(
                f"Unsupported object type '{object_type}'. "
                f"Valid types: {', '.join(sorted(self.OBJECT_TYPE_MAP))}"
            )

        if isinstance(object_names, str):
            object_names = [object_names]
        if not object_names:
            raise ValueError("At least one object name is required.")

        logger.info(
            "Searching for %s: %s",
            object_type,
            ", ".join(repr(n) for n in object_names),
        )

        matches: List[RuleMatch] = []

        for scope, rule in self.iter_security_rules():
            hits = self._rule_matches(rule, attributes, object_names)
            if not hits:
                continue

            match = RuleMatch(
                scope=scope,
                rule_name=rule.name,
                matched=hits,
                source=self._as_list(rule.source),
                destination=self._as_list(rule.destination),
                category=self._as_list(rule.category),
                source_user=self._as_list(rule.source_user),
                application=self._as_list(rule.application),
                service=self._as_list(rule.service),
                action=rule.action,
                description=getattr(rule, "description", None),
            )
            matches.append(match)
            logger.debug(
                "Match in %s -> %s (matched: %s)",
                scope, rule.name, hits,
            )

        logger.info("Found %d matching rule(s).", len(matches))
        return matches


def _format_matched(matched: Dict[str, List[str]]) -> str:
    """Render the matched dict as a compact one-line string."""
    if not matched:
        return "-"
    return "; ".join(
        f"{attr}=[{', '.join(names)}]"
        for attr, names in matched.items()
    )


def print_matches(matches: List[RuleMatch]) -> None:
    """Pretty-print a list of RuleMatch objects to stdout."""
    if not matches:
        print("No matching rules found.")
        return

    for idx, m in enumerate(matches, start=1):
        print(f"[{idx}] Scope       : {m.scope}")
        print(f"    Rule        : {m.rule_name}")
        print(f"    Action      : {m.action}")
        print(f"    Matched     : {_format_matched(m.matched)}")
        print(f"    Source      : {', '.join(m.source) or '-'}")
        print(f"    Destination : {', '.join(m.destination) or '-'}")
        print(f"    Category    : {', '.join(m.category) or '-'}")
        print(f"    Source-User : {', '.join(m.source_user) or '-'}")
        print(f"    Application : {', '.join(m.application) or '-'}")
        print(f"    Service     : {', '.join(m.service) or '-'}")
        if m.description:
            print(f"    Description : {m.description}")
        print("-" * 60)
    print(f"Total matching rules: {len(matches)}")


def print_json(matches: List[RuleMatch]) -> None:
    """Print matches as JSON."""
    print(json.dumps([m.to_dict() for m in matches], indent=2))


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Search Panorama security rules by referenced object(s)."
    )
    parser.add_argument("--host", required=True, help="Panorama IP / hostname")
    parser.add_argument("--username", required=True, help="Panorama username")
    parser.add_argument("--password", required=True, help="Panorama password")
    parser.add_argument(
        "--object-type",
        required=True,
        choices=sorted(PanoramaRuleSearcher.OBJECT_TYPE_MAP),
        help="Type of object to search for",
    )
    parser.add_argument(
        "--object-name",
        required=True,
        nargs="+",
        help=(
            "One or more object names to search for. "
            "Pass multiple values space-separated, e.g. "
            "--object-name 'CORP\\jdoe' 'CORP\\asmith' "
            "(or repeat the flag; both work). "
            "A rule matches if ANY name is found."
        ),
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL verification (not recommended)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase log verbosity (-v, -vv)",
    )
    return parser


def configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _object_names(values: Sequence[str]) -> List[str]:    
    names: List[str] = []
    for v in values:
        if v and v not in names:
            names.append(part)
    return names


def main() -> int:
    args = build_arg_parser().parse_args()
    configure_logging(args.verbose)

    object_names = _object_names(args.object_name)
    if not object_names:
        logger.error("No valid object names supplied.")
        return 2

    searcher = PanoramaRuleSearcher(
        hostname=args.host,
        username=args.username,
        password=args.password,
        verify_ssl=not args.insecure,
    )

    try:
        searcher.connect()
        matches = searcher.search(args.object_type, object_names)
    except Exception as exc:
        logger.error("Search failed: %s", exc)
        return 1

    if args.format == "json":
        print_json(matches)
    else:
        print_matches(matches)
    return 0


if __name__ == "__main__":
    sys.exit(main())
