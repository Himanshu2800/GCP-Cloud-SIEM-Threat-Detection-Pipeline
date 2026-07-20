import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

# Single source of truth for what the engine understands. detector.py
# imports SUPPORTED_OPERATORS from here rather than defining its own copy,
# so the loader's validation and the evaluator's behavior can't drift apart.
#
# This is a Sigma-compatible SUBSET, not the full Sigma spec. Extending it
# (regex, startswith, endswith, numeric comparisons, ...) is future work —
# add the operator here, implement it in evaluate_condition(), done.
SUPPORTED_OPERATORS = {"contains", "equals", "not_contains"}
SUPPORTED_CONDITION_LOGIC = {"AND", "OR"}

REQUIRED_RULE_FIELDS = {
    "title", "id", "status", "description", "author", "date",
    "severity", "mitre", "condition_logic", "conditions",
}
REQUIRED_CONDITION_FIELDS = {"field", "operator", "value"}

DEFAULT_RULES_DIR = Path(__file__).parent / "detections"


def _validate_rule(rule, source):
    """
    Validate a single parsed rule. Returns True/False; never raises.
    Any failure is logged with the source filename and rule name (when
    available) so a bad rule is easy to find and fix.
    """
    if not isinstance(rule, dict):
        logger.error(f"{source}: rule is not a YAML mapping — skipping")
        return False

    missing = REQUIRED_RULE_FIELDS - rule.keys()
    if missing:
        logger.error(f"{source}: missing required field(s) {sorted(missing)} — skipping")
        return False

    title = rule["title"]

    if not isinstance(rule["mitre"], dict) or "technique" not in rule["mitre"]:
        logger.error(
            f"{source}: rule '{title}' has a malformed 'mitre' field "
            f"(expected a mapping with a 'technique' key) — skipping"
        )
        return False

    if rule["condition_logic"] not in SUPPORTED_CONDITION_LOGIC:
        logger.error(
            f"{source}: rule '{title}' has unsupported condition_logic "
            f"'{rule['condition_logic']}' — skipping"
        )
        return False

    conditions = rule["conditions"]
    if not isinstance(conditions, list) or not conditions:
        logger.error(f"{source}: rule '{title}' has no conditions — skipping")
        return False

    for condition in conditions:
        if not isinstance(condition, dict):
            logger.error(f"{source}: rule '{title}' has a malformed condition — skipping rule")
            return False

        cond_missing = REQUIRED_CONDITION_FIELDS - condition.keys()
        if cond_missing:
            logger.error(
                f"{source}: rule '{title}' has a condition missing field(s) "
                f"{sorted(cond_missing)} — skipping rule"
            )
            return False

        if condition["operator"] not in SUPPORTED_OPERATORS:
            logger.error(
                f"{source}: rule '{title}' uses unsupported operator "
                f"'{condition['operator']}' — skipping rule"
            )
            return False

    return True


def load_rules(rules_dir=None):
    """
    Discover, parse, and validate detection rules from *.yml/*.yaml files
    in rules_dir (defaults to the detections/ folder next to this file).

    A malformed file or an invalid rule is logged and skipped — it never
    prevents the rest of the rules from loading. Call this once at
    startup; run_detections() takes the returned list as an argument
    rather than loading rules itself.
    """
    rules_dir = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
    rules = []

    if not rules_dir.is_dir():
        logger.error(f"Rules directory '{rules_dir}' not found — loading zero rules")
        return rules

    rule_files = sorted(rules_dir.glob("*.yml")) + sorted(rules_dir.glob("*.yaml"))

    for path in rule_files:
        try:
            with path.open("r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.error(f"{path.name}: failed to parse YAML ({e}) — skipping")
            continue
        except OSError as e:
            logger.error(f"{path.name}: failed to read file ({e}) — skipping")
            continue

        if _validate_rule(rule, path.name):
            rules.append(rule)

    logger.info(f"Loaded {len(rules)} detection rule(s) from {rules_dir}")
    return rules
