from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_repository_root_has_no_loose_files():
    visible = {path.name for path in ROOT.iterdir() if not path.name.startswith(".")}
    assert visible == {
        "README.md",
        "artifacts",
        "config",
        "data",
        "docs",
        "src",
        "tests",
        "tools",
    }
    assert {path.name for path in ROOT.iterdir() if not path.name.startswith(".") and path.is_file()} == {
        "README.md"
    }


def test_controller_and_sigma_modules_live_inside_package():
    expected = {
        "pipeline/controller.py",
        "pipeline/legacy.py",
        "report_agent.py",
        "contracts.py",
        "sigma/retrieval.py",
        "sigma/coverage.py",
        "sigma/agent.py",
        "sigma/executor.py",
        "telemetry/otrf.py",
        "rule_generation/generator.py",
        "rule_generation/review.py",
    }
    assert {path for path in expected if not (ROOT / "src" / "threat2detect" / path).is_file()} == set()
