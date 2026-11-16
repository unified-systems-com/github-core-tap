"""Shared test scaffolding for the github_core plugin's suite."""


def dimension_view(entity) -> dict:
    """An entity's dimensions as ``{name: value}``, whichever way the grid under test stores them.

    A grid from tap 0.3.4 or earlier stores that map directly. A later one keys it by Dimension
    node and wraps each value; its own ``view`` turns that back into names and values.
    """
    try:
        from tap_grid.dimension_names import view
    except ImportError:
        return dict(entity.dimensions or {})
    return view(entity.dimensions)


def dimension_containment(name: str, value: str) -> dict:
    """The ``dimensions__contains`` fragment matching rows that carry ``name`` = ``value``, for the grid under test."""
    try:
        from tap_grid.dimension_names import containment
    except ImportError:
        return {name: value}
    return containment(name, value)
