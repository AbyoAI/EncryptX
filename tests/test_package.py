from pathlib import Path


def test_readme_exists():
    assert Path("README.md").is_file()


def test_requirements_lists_cryptography():
    requirements = Path("requirements.txt").read_text(encoding="utf-8")
    assert "cryptography" in requirements.lower()
