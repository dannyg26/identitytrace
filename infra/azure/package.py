"""Create a source deployment ZIP from an explicit allowlist; never include local data."""

import argparse
import zipfile
from pathlib import Path


def package(destination):
    root = Path(__file__).resolve().parents[2]
    sources = [root / name for name in ("pyproject.toml", "requirements.txt")]
    for directory in ("app", "scripts", "detections", "correlations", "dashboard", "infra/azure"):
        sources.extend(path for path in (root / directory).rglob("*")
                       if path.is_file() and path.suffix in {".py", ".yaml", ".html", ".css", ".js"}
                       and "__pycache__" not in path.parts)
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(sources):
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                raise ValueError("Refusing a source link outside the project")
            archive.write(path, path.relative_to(root).as_posix())
    print(f"Packaged {len(sources)} source files; no deployments, databases, caches or datasets.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    package(parser.parse_args().destination)
