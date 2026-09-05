"""ATT&CK and ATLAS technique validation.

Nothing that looks like a technique ID reaches a Bishop report without passing
through `validate_techniques` (ATT&CK) or `validate_atlas` (ATLAS). See
`catalogue.py` for why that rule is absolute.
"""

from bishop.attck.atlas import (
    ATLAS_SOURCE,
    ATLAS_TECHNIQUES,
    ATLAS_VERSION,
    AtlasTechnique,
    atlas_for_signals,
    is_atlas_id,
    validate_atlas,
)
from bishop.attck.catalogue import (
    TECHNIQUE_PATTERN,
    Rejection,
    Technique,
    TechniqueCatalogue,
    TechniqueRejected,
    Validation,
    load_catalogue,
    validate_techniques,
)
from bishop.attck.coverage import CoverageMatrix, TechniqueCoverage, build_matrix, render_markdown

__all__ = [
    "ATLAS_SOURCE",
    "ATLAS_TECHNIQUES",
    "ATLAS_VERSION",
    "TECHNIQUE_PATTERN",
    "AtlasTechnique",
    "CoverageMatrix",
    "Rejection",
    "Technique",
    "TechniqueCatalogue",
    "TechniqueCoverage",
    "TechniqueRejected",
    "Validation",
    "atlas_for_signals",
    "build_matrix",
    "is_atlas_id",
    "load_catalogue",
    "render_markdown",
    "validate_atlas",
    "validate_techniques",
]
