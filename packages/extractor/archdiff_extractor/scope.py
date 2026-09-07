"""Scope resolution (SCHEMA.md section 1).

A scope is resolved PER RESOURCE from its ``provider_config_key``, following
the precedence chain

    explicit -> provider_config -> terragrunt_unit -> variable_heuristic -> fallback

``source`` and ``confidence`` are reported honestly: a scope whose account id
was inferred from a variable name is ``low`` even if it happens to be right.

``root_module`` is informational and never enters ``key`` or any digest.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional, Set, Tuple

from .plan import Plan, module_parent_chain
from .references import collect_references, constant_of

ACCOUNT_RE = re.compile(r"^\d{12}$")
REGION_RE = re.compile(r"^(?:us|eu|ap|sa|ca|me|af|il|mx|cn|us-gov|us-iso|us-isob)-[a-z]+-\d$")
ARN_RE = re.compile(r"^arn:(?P<partition>[^:]+):(?P<service>[^:]*):(?P<region>[^:]*):(?P<account>[^:]*):(?P<rest>.*)$")

ACCOUNT_VARIABLE_NAMES = ("account_id", "aws_account_id", "account", "target_account_id")
ENV_VARIABLE_NAMES = ("environment", "env", "stage")

UNKNOWN = "unknown"


@dataclass(frozen=True)
class Scope:
    key: str
    partition: str
    account_id: Optional[str]
    region: Optional[str]
    source: str
    confidence: str
    root_module: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "partition": self.partition,
            "account_id": self.account_id,
            "region": self.region,
            "source": self.source,
            "confidence": self.confidence,
            "root_module": self.root_module,
        }


def make_key(partition: str, account_label: Optional[str], region: Optional[str]) -> str:
    return f"{partition}:{account_label or UNKNOWN}:{region or UNKNOWN}"


def partition_for_region(region: Optional[str]) -> str:
    if not region:
        return "aws"
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if region.startswith("us-iso-"):
        return "aws-iso"
    if region.startswith("us-isob-"):
        return "aws-iso-b"
    return "aws"


def parse_arn(arn: str) -> Optional[Dict[str, str]]:
    m = ARN_RE.match(arn or "")
    return m.groupdict() if m else None


@dataclass
class ProviderFacts:
    """What a provider block tells us, after resolving variables."""
    region: Optional[str] = None
    account_id: Optional[str] = None
    partition: Optional[str] = None
    profile: Optional[str] = None
    consumed_variables: Tuple[str, ...] = ()
    found: bool = False


class ScopeResolver:
    """Resolve scopes for one plan. Memoised per provider_config_key."""

    def __init__(self, plan: Plan, *, explicit: Optional[Dict[str, Dict[str, Any]]] = None,
                 terragrunt_working_dir: Optional[str] = None, repo_root: Optional[str] = None,
                 root_module: Optional[str] = None, env: Optional[Dict[str, str]] = None):
        self.plan = plan
        self.explicit = explicit or {}
        env = os.environ if env is None else env
        self.terragrunt_working_dir = terragrunt_working_dir or env.get("TERRAGRUNT_WORKING_DIR") or None
        self.repo_root = repo_root
        self.root_module = root_module
        self.warnings: List[str] = []
        self._cache: Dict[str, Scope] = {}
        self._facts_cache: Dict[str, ProviderFacts] = {}
        # Variables consumed by a provider block that DID resolve an account.
        # The variable heuristic must not reuse them for a different provider,
        # or an aliased provider pointing at another account silently collapses
        # into the default provider's scope.
        self._consumed: Dict[str, Set[str]] = {}

    # -- public -------------------------------------------------------------

    def resolve(self, provider_config_key: str) -> Scope:
        if provider_config_key in self._cache:
            return self._cache[provider_config_key]
        self._prime_consumed()
        scope = self._resolve_uncached(provider_config_key)
        scope = replace(scope, root_module=self.root_module)
        self._cache[provider_config_key] = scope
        return scope

    def default_root_module(self) -> Optional[str]:
        """Terragrunt unit path is the best informational label when present."""
        if self.terragrunt_working_dir:
            return self._unit_label()
        return None

    # -- precedence chain ---------------------------------------------------

    def _resolve_uncached(self, key: str) -> Scope:
        facts = self._provider_facts(key)
        region = facts.region
        partition = facts.partition or partition_for_region(region)

        # 1. explicit
        exp = self._explicit_for(key)
        if exp is not None:
            account = exp.get("account_id")
            region = exp.get("region", region)
            partition = exp.get("partition", partition)
            return Scope(make_key(partition, account, region), partition, account, region,
                         "explicit", "high")

        # 2. provider_config
        if facts.account_id:
            return Scope(make_key(partition, facts.account_id, region), partition,
                         facts.account_id, region, "provider_config", "high")
        if facts.profile:
            # A profile names a credential set, not an account. We do NOT read
            # ~/.aws/config (ambient state); the scope is keyed on the profile.
            return Scope(make_key(partition, f"profile={facts.profile}", region), partition,
                         None, region, "provider_config", "medium")

        # 3. terragrunt_unit
        if self.terragrunt_working_dir:
            account, tg_region, label = self._terragrunt_facts()
            region = region or tg_region
            partition = facts.partition or partition_for_region(region)
            if account:
                return Scope(make_key(partition, account, region), partition, account, region,
                             "terragrunt_unit", "medium")
            return Scope(make_key(partition, f"unit={label}", region), partition, None, region,
                         "terragrunt_unit", "medium")

        # 4. variable_heuristic -- only when NO provider block in this plan
        # resolved an account. If one did, every provider that did not is a
        # deliberately different target (an aliased provider for another
        # account) and plan-wide variables must not be applied to it.
        others_resolved = any(k != key and k != "__primed__" for k in self._consumed)
        if not others_resolved:
            for name in ACCOUNT_VARIABLE_NAMES:
                value = self.plan.variables.get(name)
                if not isinstance(value, str) or not ACCOUNT_RE.match(value):
                    continue
                return Scope(make_key(partition, value, region), partition, value, region,
                             "variable_heuristic", "low")
            for name in ENV_VARIABLE_NAMES:
                value = self.plan.variables.get(name)
                if not isinstance(value, str) or not value:
                    continue
                return Scope(make_key(partition, f"env={value}", region), partition, None, region,
                             "variable_heuristic", "low")

        # 5. fallback
        return Scope(make_key(partition, None, region), partition, None, region,
                     "fallback", "low")

    # -- explicit -----------------------------------------------------------

    def _explicit_for(self, key: str) -> Optional[Dict[str, Any]]:
        if key in self.explicit:
            return self.explicit[key]
        local = key.rsplit(":", 1)[-1]
        if local in self.explicit:
            return self.explicit[local]
        return self.explicit.get("*")

    # -- provider_config ----------------------------------------------------

    def _prime_consumed(self) -> None:
        if self._consumed:
            return
        for key in self.plan.provider_config:
            facts = self._provider_facts(key)
            if facts.account_id:
                self._consumed[key] = set(facts.consumed_variables)
        if not self._consumed:
            self._consumed["__primed__"] = set()

    def _provider_facts(self, key: str) -> ProviderFacts:
        if key in self._facts_cache:
            return self._facts_cache[key]
        facts = ProviderFacts()
        for candidate in self._inheritance_chain(key):
            entry = self.plan.provider_config.get(candidate)
            if entry is None:
                continue
            f = self._facts_from_entry(entry)
            if not facts.found:
                facts = f
            else:
                # Inherit only what the more specific block did not set.
                facts = ProviderFacts(
                    region=facts.region or f.region,
                    account_id=facts.account_id or f.account_id,
                    partition=facts.partition or f.partition,
                    profile=facts.profile or f.profile,
                    consumed_variables=tuple(sorted(set(facts.consumed_variables) | set(f.consumed_variables))),
                    found=True)
            if facts.account_id or facts.profile:
                break
        self._facts_cache[key] = facts
        return facts

    @staticmethod
    def _inheritance_chain(key: str) -> List[str]:
        """``module.a.module.b:aws.x`` -> [itself, ``module.a:aws.x``, ``aws.x``]."""
        if ":" not in key:
            return [key]
        module_path, local = key.rsplit(":", 1)
        chain = []
        for m in module_parent_chain(module_path):
            chain.append(f"{m}:{local}" if m else local)
        return chain

    def _facts_from_entry(self, entry: Dict[str, Any]) -> ProviderFacts:
        expr = entry.get("expressions") or {}
        consumed: Set[str] = set()
        facts = ProviderFacts(found=True)

        region = self._eval(expr.get("region"), consumed)
        if isinstance(region, str) and region:
            facts.region = region

        account = None
        partition = None
        allowed = self._eval(expr.get("allowed_account_ids"), consumed)
        if isinstance(allowed, (list, tuple)):
            ids = [a for a in allowed if isinstance(a, str) and ACCOUNT_RE.match(a)]
            if len(ids) > 1:
                self.warnings.append(
                    f"provider {entry.get('name')}: allowed_account_ids lists {len(ids)} accounts; "
                    f"using the first ({ids[0]})")
            if ids:
                account = ids[0]
        elif isinstance(allowed, str) and ACCOUNT_RE.match(allowed):
            account = allowed

        for block_name in ("assume_role", "assume_role_with_web_identity"):
            if account:
                break
            blocks = expr.get(block_name)
            if isinstance(blocks, dict):
                blocks = [blocks]
            for block in blocks or []:
                role_arn = self._eval((block or {}).get("role_arn"), consumed)
                arn = parse_arn(role_arn) if isinstance(role_arn, str) else None
                if arn and ACCOUNT_RE.match(arn["account"]):
                    account = arn["account"]
                    partition = arn["partition"]
                    break

        profile = self._eval(expr.get("profile"), consumed)
        if isinstance(profile, str) and profile:
            facts.profile = profile

        facts.account_id = account
        facts.partition = partition
        facts.consumed_variables = tuple(sorted(consumed))
        return facts

    def _eval(self, expr: Any, consumed: Set[str]) -> Any:
        """Evaluate a provider expression: constant, or var.* against top-level variables."""
        if expr is None:
            return None
        has_const, value = constant_of(expr)
        if has_const:
            return value
        values: List[Any] = []
        for ref in collect_references(expr):
            if ref.startswith("var."):
                name = ref[4:].split(".")[0].split("[")[0]
                if name in self.plan.variables:
                    consumed.add(name)
                    values.append(self.plan.variables[name])
                else:
                    default = (self.plan.config.variables.get(name) or {}).get("default")
                    if default is not None:
                        consumed.add(name)
                        values.append(default)
        if not values:
            return None
        if len(values) == 1:
            return values[0]
        return values

    # -- terragrunt ---------------------------------------------------------

    def _terragrunt_facts(self) -> Tuple[Optional[str], Optional[str], str]:
        path = self.terragrunt_working_dir or ""
        segments = [s for s in re.split(r"[\\/]", path) if s]
        account = next((s for s in segments if ACCOUNT_RE.match(s)), None)
        region = next((s for s in reversed(segments) if REGION_RE.match(s)), None)
        return account, region, self._unit_label()

    def _unit_label(self) -> str:
        path = os.path.normpath(self.terragrunt_working_dir or "")
        if self.repo_root:
            try:
                rel = os.path.relpath(path, self.repo_root)
                if not rel.startswith(".."):
                    return rel.replace(os.sep, "/")
            except ValueError:
                pass
        return path.replace(os.sep, "/")
