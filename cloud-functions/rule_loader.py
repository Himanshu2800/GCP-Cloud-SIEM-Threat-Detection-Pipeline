import logging
import re
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)
SUPPORTED_OPERATORS = {"contains", "equals", "not_contains"}
SUPPORTED_CONDITION_LOGIC = {"AND", "OR"}

REQUIRED_RULE_FIELDS = {
    "title", "rule_id", "id", "status", "description", "author", "date",
    "severity", "mitre", "condition_logic", "conditions",
}
REQUIRED_CONDITION_FIELDS = {"field", "operator", "value"}
_RULE_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
DEFAULT_RULES_DIR = Path(__file__).parent / "detections"

def _validate_rule(rule, source):
    if not isinstance(rule, dict):
        logger.error(f"{source}: rule is not a YAML mapping, skipping")
        return False

    missing = REQUIRED_RULE_FIELDS - rule.keys()
    if missing:
        logger.error(f"{source}: missing required field(s) {sorted(missing)}, skipping")
        return False

    title = rule["title"]

    if not _RULE_ID_PATTERN.match(str(rule["rule_id"])):
        logger.error(
            f"{source}: rule '{title}' has an invalid rule_id "
            f"'{rule['rule_id']}' (must be UPPER_SNAKE_CASE), skipping"
        )
        return False

    if not isinstance(rule["mitre"], dict) or "technique" not in rule["mitre"]:
        logger.error(
            f"{source}: rule '{title}' has a malformed 'mitre' field "
            f"(expected a mapping with a 'technique' key), skipping"
        )
        return False

    if rule["condition_logic"] not in SUPPORTED_CONDITION_LOGIC:
        logger.error(
            f"{source}: rule '{title}' has unsupported condition_logic "
            f"'{rule['condition_logic']}', skipping"
        )
        return False

    conditions = rule["conditions"]
    if not isinstance(conditions, list) or not conditions:
        logger.error(f"{source}: rule '{title}' has no conditions, skipping")
        return False

    for condition in conditions:
        if not isinstance(condition, dict):
            logger.error(f"{source}: rule '{title}' has a malformed condition, skipping rule")
            return False

        cond_missing = REQUIRED_CONDITION_FIELDS - condition.keys()
        if cond_missing:
            logger.error(
                f"{source}: rule '{title}' has a condition missing field(s) "
                f"{sorted(cond_missing)}, skipping rule"
            )
            return False

        if condition["operator"] not in SUPPORTED_OPERATORS:
            logger.error(
                f"{source}: rule '{title}' uses unsupported operator "
                f"'{condition['operator']}', skipping rule"
            )
            return False

    return True


def load_rules(rules_dir=None):
    rules_dir = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
    rules = []

    if not rules_dir.is_dir():
        logger.error(f"Rules directory '{rules_dir}' not found, loading zero rules")
        return rules

    rule_files = sorted(rules_dir.glob("*.yml")) + sorted(rules_dir.glob("*.yaml"))

    for path in rule_files:
        try:
            with path.open("r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.error(f"{path.name}: failed to parse YAML ({e}), skipping")
            continue
        except OSError as e:
            logger.error(f"{path.name}: failed to read file ({e}), skipping")
            continue

        if _validate_rule(rule, path.name):
            rules.append(rule)

    _check_duplicate_rule_ids(rules)

    logger.info(f"Loaded {len(rules)} detection rule(s) from {rules_dir}")
    return rules
def _check_duplicate_rule_ids(rules):
    seen = {}
    for rule in rules:
        rid = rule["rule_id"]
        if rid in seen:
            logger.error(
                f"Duplicate rule_id '{rid}' used by both "
                f"'{seen[rid]}' and '{rule['title']}', rule_id must be "
                f"unique across all detection rules"
            )
        else:
            seen[rid] = rule["title"]
