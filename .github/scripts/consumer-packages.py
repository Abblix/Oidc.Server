"""Make a consumer's project restore the Abblix packages this release run packed, and prove it did.

The release workflow builds what a reader builds - the getting-started samples, the templates' scaffolds, a
`dotnet new web` project - against the packages in the run's artifact, never against a feed. The commands:

  use-local <folder>            writes the user-level NuGet configuration: Abblix.* from <folder> only, every
                                other package from nuget.org. The source mapping is what makes it the run's
                                packages: without it a restore may take a same-numbered package from the feed,
                                which is exactly the case once a re-run follows a publish.
  count <dir>                   prints how many Abblix package references the projects under <dir> hold.
  point <version> <dir>         sets every Abblix package reference of every project under <dir> to <version>.
                                The references are read from MSBuild's own evaluation and written by
                                `dotnet add package`, so no project file is parsed or edited by hand.
  verify <folder> <version>     after a restore: every Abblix package in the global packages folder is
                                <version> and came from <folder>, and there is at least one.
"""

import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path

PREFIX = "abblix."
SKIPPED_DIRECTORIES = {"bin", "obj", "node_modules", ".git"}


def use_local(folder: Path) -> int:
    if not any(folder.glob("*.nupkg")):
        print(f"::error::{folder} holds no .nupkg, so there is nothing of this run to restore. Skipped step: the "
              "packages the build-and-pack job uploads as nuget-packages - fix the pack on the release branch and "
              "dispatch the release again", file=sys.stderr)
        return 1
    configuration = ElementTree.Element("configuration")
    sources = ElementTree.SubElement(configuration, "packageSources")
    ElementTree.SubElement(sources, "clear")
    ElementTree.SubElement(sources, "add", key="this-run", value=str(folder.resolve()))
    ElementTree.SubElement(sources, "add", key="nuget.org", value="https://api.nuget.org/v3/index.json")
    mapping = ElementTree.SubElement(configuration, "packageSourceMapping")
    # The longer pattern wins, so an Abblix package can come from this run's folder and nowhere else
    ElementTree.SubElement(ElementTree.SubElement(mapping, "packageSource", key="this-run"), "package", pattern="Abblix.*")
    ElementTree.SubElement(ElementTree.SubElement(mapping, "packageSource", key="nuget.org"), "package", pattern="*")
    path = Path.home() / ".nuget" / "NuGet" / "NuGet.Config"
    path.parent.mkdir(parents=True, exist_ok=True)
    ElementTree.ElementTree(configuration).write(path, encoding="utf-8", xml_declaration=True)
    print(f"{path}: Abblix.* from {folder.resolve()} only, everything else from nuget.org")
    return 0


def projects_under(root: Path):
    for directory, subdirectories, files in os.walk(root):
        subdirectories[:] = [name for name in subdirectories if name not in SKIPPED_DIRECTORIES]
        for name in files:
            if name.endswith(".csproj"):
                yield Path(directory) / name


class DotnetFailed(Exception):
    """A dotnet command refused; its own output is printed, since MSBuild writes its errors to stdout."""


def dotnet(arguments: list[str]) -> str:
    completed = subprocess.run(["dotnet", *arguments], capture_output=True, text=True)
    if completed.returncode != 0:
        print(completed.stdout, completed.stderr, sep="\n", file=sys.stderr)
        raise DotnetFailed(f"dotnet {' '.join(arguments)} exited with {completed.returncode}; its output is above")
    return completed.stdout


def abblix_references(project: Path) -> list[str]:
    evaluated = dotnet(["msbuild", str(project), "-getItem:PackageReference"])
    items = json.loads(evaluated).get("Items", {}).get("PackageReference", [])
    return [item["Identity"] for item in items if item["Identity"].lower().startswith(PREFIX)]


def point(version: str, root: Path) -> int:
    pointed = 0
    for project in sorted(projects_under(root)):
        for package in abblix_references(project):
            dotnet(["add", str(project), "package", package, "--version", version, "--no-restore"])
            print(f"{project.relative_to(root)}: {package} {version}")
            pointed += 1
    if pointed == 0:
        print(f"::error::No project under {root} references an Abblix package, so nothing here would test "
              "this run's packages. Skipped step: a consumer project that installs the Abblix packages - when the "
              "repository dropped them, fix the job in .github/workflows/release.yml on the release branch and "
              "dispatch the release again", file=sys.stderr)
        return 1
    return 0


def verify(folder: Path, version: str) -> int:
    packages = Path(os.environ.get("NUGET_PACKAGES") or Path.home() / ".nuget" / "packages")
    expected = str(folder.resolve()).rstrip("/")
    found, wrong = 0, []
    restored_packages = packages.iterdir() if packages.is_dir() else []
    for package in sorted(path for path in restored_packages if path.name.startswith(PREFIX)):
        for restored in package.iterdir():
            metadata = json.loads((restored / ".nupkg.metadata").read_text(encoding="utf-8"))
            source = str(metadata.get("source", "")).rstrip("/")
            found += 1
            if restored.name != version.lower() or source != expected:
                wrong.append(f"{package.name} {restored.name} from {source or 'an unknown source'}")
    if wrong:
        print(f"::error::Restored Abblix packages that are not this run's {version} from {expected}: "
              + "; ".join(wrong) + ". Skipped step: restore through the configuration the step 'Restore Abblix "
              "packages from this run only' writes - a nuget.config of the consumer repository that adds sources "
              "or mappings overrides it, so remove it there and re-run this job; a reference this job did not "
              "point at the run's version is fixed in .github/workflows/release.yml on the release branch, then "
              "the release is dispatched again", file=sys.stderr)
        return 1
    if found == 0:
        print(f"::error::{packages} holds no Abblix package, so nothing was restored from this run. Skipped step: "
              "the build of the consumer projects before this check, after the step 'Restore Abblix packages from "
              "this run only' - fix the order in .github/workflows/release.yml on the release branch and dispatch "
              "the release again", file=sys.stderr)
        return 1
    print(f"{found} Abblix packages restored, each {version} from {expected}")
    return 0


def main(arguments: list[str]) -> int:
    match arguments:
        case ["use-local", folder]:
            return use_local(Path(folder))
        case ["count", root]:
            print(sum(len(abblix_references(project)) for project in projects_under(Path(root).resolve())))
            return 0
        case ["point", version, root]:
            return point(version, Path(root).resolve())
        case ["verify", folder, version]:
            return verify(Path(folder), version)
        case _:
            print(__doc__, file=sys.stderr)
            return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except DotnetFailed as failure:
        print(f"::error::{failure}. Skipped step: the project it names must evaluate and accept this run's "
              "packages - reproduce with the same command in that repository, fix the project there, then re-run "
              "this job; when the library's packages are at fault, fix them on the release branch and dispatch "
              "the release again", file=sys.stderr)
        sys.exit(1)
