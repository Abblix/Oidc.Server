# Abblix.Analyzers

Roslyn analyzers that hold the Abblix house rules for C#. Every rule is a build error, so it is reported the same way in the IDE, in a local build and in CI.

| Rule | What it refuses | Instead |
|---|---|---|
| RS0030 | Reading the time from `DateTime.Now`, `DateTime.UtcNow`, `DateTime.Today`, `DateTimeOffset.Now` or `DateTimeOffset.UtcNow` | An injected `TimeProvider`, so a test can move the time |
| ABX1001 | A `#region` directive | Split the file or the type |
| ABX1002 | A type deriving from `TimeProvider` | `TimeProvider.System` in production, `FakeTimeProvider` from Microsoft.Extensions.TimeProvider.Testing in tests |

RS0030 comes from Microsoft.CodeAnalysis.BannedApiAnalyzers, which this package brings along together with its list of banned members.

## Use

```xml
<PackageReference Include="Abblix.Analyzers" PrivateAssets="all" />
```

A rule a project really has to break is suppressed at the site, with the reason beside it.
