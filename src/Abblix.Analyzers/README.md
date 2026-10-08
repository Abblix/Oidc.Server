# Abblix.Analyzers

Roslyn analyzers that hold the Abblix house rules for C#. Every rule is a build error, so it is reported the same way in the IDE, in a local build and in CI.

| Rule | What it refuses | Instead |
|---|---|---|
| RS0030 | Reading the time from `DateTime.Now`, `DateTime.UtcNow`, `DateTime.Today`, `DateTimeOffset.Now` or `DateTimeOffset.UtcNow` | An injected `TimeProvider`, so a test can move the time |
| ABX1001 | A `#region` directive | Split the file or the type |
| ABX1002 | A type deriving from `TimeProvider` | `TimeProvider.System` in production, `FakeTimeProvider` from Microsoft.Extensions.TimeProvider.Testing in tests |
| ABX1003 | A conditional expression whose condition compares an enum with one of its members, such as `level == Level.Hard ? "hard" : "soft"` | A `switch` that names every member and throws in its default arm |
| ABX1004 | A `switch` on an enum that leaves some members to the default arm | Name every member; keep the default for a throw |
| ABX1005 | An expression joining more than three conditions with `&&`, `\|\|` and `?:` | Name a part of it: a local, a method, a property |
| ABX1006 | A declaration whose documentation comment holds more than one `<summary>` | Keep one; the other usually belongs to the declaration next to it |

RS0030 comes from Microsoft.CodeAnalysis.BannedApiAnalyzers, which this package brings along together with its list of banned members. ABX1002 checks generated code as well; ABX1001 leaves it alone, because generators such as the gRPC tooling write regions of their own.

ABX1005 replaces Sonar's S1067, which also counts the `or` and `and` combinators of a pattern, taking the pattern as an expression of its own. S1067 is off unless a configuration raises it, so a project moving to this package removes the line that does. A pattern listing the cases one arm answers alike reads as a list rather than as conditions to combine, and counting it would force an exhaustive switch apart into arms that repeat one answer. An argument, a switch arm, a guard, an interpolation hole, a lambda body and each member an initializer sets are each judged as an expression of their own. Unlike S1067, the count goes on through a cast, a member access on a parenthesized expression, the null-forgiving `!` and `checked(...)`, since what they wrap is still read as part of the condition.

ABX1003 and ABX1004 exist for the member somebody adds later. A conditional on one member sends it to the second branch, and a default arm answers for it, with nothing reported in either case. A switch that names every member stops compiling there instead. Both rules apply only to enums of your own product: declared in the assembly being built, or in one whose name starts with the same first segment, so `Contoso.Domain` counts for `Contoso.Web`. That holds the same in the IDE and in a build. The first segment names the vendor rather than one product, so `Contoso.Web` is also held to the rule for an enum of a separately shipped `Contoso.Messaging` package it references. An enum from anywhere else is exempt: there, dispatching on a few values and refusing the rest is the right shape, for example with a JSON token type. ABX1003 treats an ordering comparison (`>=`) and two member tests joined by `||` as picking by a member too. A `[Flags]` enum is exempt as well, because testing a bit is not choosing a member. A test for null or for a `bool` is never reported, since neither one can gain a value. A guarded arm (`when`) still counts as naming its member.

## Use

The package is published to the Abblix GitHub feed (`https://nuget.pkg.github.com/Abblix/index.json`) by every dev build, from `develop` and from release branches, and is not part of a library release.

```xml
<PackageReference Include="Abblix.Analyzers" PrivateAssets="all" />
```

A project moving to this package deletes, in the same change, the copies of these rules it kept itself: the clock reads in its own `BannedSymbols.txt` (BannedApiAnalyzers refuses a member listed twice with RS0031), a StyleCop reference kept for SA1124, and any test that searched the sources for regions or clocks.

A rule a project really has to break is suppressed at the site, with the reason beside it.
