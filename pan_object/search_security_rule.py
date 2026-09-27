#!/usr/bin/env python3
"""
search_security_rules.py

Search Panorama Security policy rules that reference a specific object
(address, URL category, source user, application, service, etc.)

Usage:
    python search_security_rules.py \
        --host panorama.example.com \
        --username admin \
        --password secret \
        --object-type address \
        --object-name web-servers

Dependencies:
    pan-os-python (pip install pan-os-python)
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, List, Optional, Tuple

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
    and every device-group rulebase) for a referenced object.
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

        if self.api_version:
            self._pano.add()

        self._pano.refresh_system_info()
        logger.info("Connected to Panorama %s", self.hostname)
        return self._pano

    @property
    def panorama(self) -> Panorama:
        if self._pano is None:
            raise RuntimeError("Not connected. Call connect() first.")
        return self._pano

    def iter_security_rules(self) -> Iterable[Tuple[str, SecurityRule]]:
        """
        Yield (scope_description, SecurityRule) for every security rule
        on Panorama.
        """
        pano = self.panorama

        # Panorama-level rulebases
        for scope, rulebase_cls in (
            ("Panorama pre-rulebase", PreRulebase),
            ("Panorama post-rulebase", PostRulebase),
        ):
            rulebase = pano.add(rulebase_cls())
            for rule in SecurityRule.refreshall(rulebase):
                yield scope, rule

        # Device-group rulebases
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
        attributes: List[str],
        object_name: str,
    ) -> bool:
        """Return True if any of the given attributes contain object_name."""
        for attr in attributes:
            members = self._as_list(getattr(rule, attr, None))
            if object_name in members:
                return True
        return False


    def search(
        self,
        object_type: str,
        object_name: str,
    ) -> List[RuleMatch]:
        """
        Search all security rules for the given object reference.

        :param object_type: One of OBJECT_TYPE_MAP keys.
        :param object_name: Name of the object to search for.
        :returns: List of RuleMatch objects.
        """
        attributes = self.OBJECT_TYPE_MAP.get(object_type)
        if not attributes:
            raise ValueError(
                f"Unsupported object type '{object_type}'. "
                f"Valid types: {', '.join(sorted(self.OBJECT_TYPE_MAP))}"
            )

        logger.info("Searching for %s '%s' …", object_type, object_name)
        matches: List[RuleMatch] = []

        for scope, rule in self.iter_security_rules():
            if not self._rule_matches(rule, attributes, object_name):
                continue

            match = RuleMatch(
                scope=scope,
                rule_name=rule.name,
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
            logger.debug("Match in %s -> %s", scope, rule.name)

        logger.info("Found %d matching rule(s).", len(matches))
        return matches


def print_matches(matches: List[RuleMatch]) -> None:
    """Pretty-print a list of RuleMatch objects to stdout."""
    if not matches:
        print("No matching rules found.")
        return

    for idx, m in enumerate(matches, start=1):
        print(f"[{idx}] Scope       : {m.scope}")
        print(f"    Rule        : {m.rule_name}")
        print(f"    Action      : {m.action}")
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


# CLI
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Search Panorama security rules by referenced object."
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
        help="Name of the object (e.g. 'web-servers', 'social-networking')",
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


def main() -> int:
    args = build_arg_parser().parse_args()
    configure_logging(args.verbose)

    searcher = PanoramaRuleSearcher(
        hostname=args.host,
        username=args.username,
        password=args.password,
        verify_ssl=not args.insecure,
    )

    try:
        searcher.connect()
        matches = searcher.search(args.object_type, args.object_name)
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
