"""Field-schema fragments shared by the models.

A timestamp is declared once, with `format: date-time`, so Gryphon's MIN and MAX accept it: a field
declared as a plain string is refused ("is declared {string}"). The grid does not enforce the format on
write, so a stored value is unchanged by it. Null is "not observed", never "now".
"""

from typing import Any, Final

DATE_TIME: Final[dict[str, Any]] = {"type": ["string", "null"], "format": "date-time"}
"""A nullable timestamp, for `FIELD_CRUD_SCHEMA`."""

DATE_TIME_VALIDATION: Final[dict[str, Any]] = {"validation": "jsonschema", "schema": DATE_TIME}
"""The same timestamp, for `FIELD_VALIDATION_SCHEMA`."""


def timestamps(*names: str) -> dict[str, dict[str, Any]]:
    """`FIELD_CRUD_SCHEMA` entries for several timestamp fields."""
    return dict.fromkeys(names, DATE_TIME)


def timestamp_validations(*names: str) -> dict[str, dict[str, Any]]:
    """`FIELD_VALIDATION_SCHEMA` entries for several timestamp fields."""
    return dict.fromkeys(names, DATE_TIME_VALIDATION)
