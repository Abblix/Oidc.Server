# Abblix.Analyzers

Roslyn analyzers that hold the Abblix house rules for C#. Every rule is a build error, so it is reported the same way in the IDE, in a local build and in CI.

| Rule | What it refuses | Instead |
|---|---|---|
| RS0030 | Reading the time from `DateTime.Now`, `DateTime.UtcNow`, `DateTime.Today`, `DateTimeOffset.Now` or `DateTimeOffset.UtcNow` | An injected `TimeProvider`, so a test can move the time |
| ABX1001 | A `#region` directive | Split the file or the type |
| ABX1002 | A type deriving from `TimeProvider` | `TimeProvider.System` in production, `FakeTimeProvider` from Microsoft.Extensions.TimeProvider.Testing in tests |

RS0030 comes from Microsoft.CodeAnalysis.BannedApiAnalyzers, which this package brings along together with its list of banned members. ABX1002 checks generated code as well; ABX1001 leaves it alone, because generators such as the gRPC tooling write regions of their own.

## Use

The package is published to the Abblix GitHub feed (`https://nuget.pkg.github.com/Abblix/index.json`) from every build of `develop`, and is not part of a library release.

```xml
<PackageReference Include="Abblix.Analyzers" PrivateAssets="all" />
```

A project moving to this package deletes, in the same change, the copies of these rules it kept itself: the clock reads in its own `BannedSymbols.txt` (BannedApiAnalyzers refuses a member listed twice with RS0031), a StyleCop reference kept for SA1124, and any test that searched the sources for regions or clocks.

A rule a project really has to break is suppressed at the site, with the reason beside it.
