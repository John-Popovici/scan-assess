from ngo_intel.agent_brief import generate_agent_context
from ngo_intel.normalize import normalize_all
from ngo_intel.paths import ProjectPaths
from ngo_intel.scoring import score_all


def test_brief_file_is_generated_and_contains_top_risks() -> None:
    paths = ProjectPaths.discover()
    normalize_all(paths)
    score_all(paths)
    generate_agent_context(paths)
    brief = paths.agent_context_dir / "current" / "intel_brief.md"
    assert brief.exists()
    assert "## Top Risks" in brief.read_text(encoding="utf-8")
