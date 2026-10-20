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
| ABX1007 | A `[LoggerMessage]` argument carrying a value read from a type marked `[ExternalInput]`, passed as anything but `Sanitized` | Declare the parameter as `Sanitized`, or a list or array of it |
| ABX1008 | A `[LoggerMessage]` argument carrying a value read from a member or parameter marked `[Credential]`, passed as anything but `Fingerprint` | Declare the parameter as `Fingerprint` and pass the fingerprint of the value |
| ABX1009 | A call to the OIDC server's entity storage for a type no Protocol Buffers codec serves | Add a codec to the registry, or mark the type `[StoredAsJson]` with the reason |
| ABX1010 | A field of a stored message, or a property of a stored type, that the codec's mapper leaves out of the way to the message or the way back | Map it both ways, or mark the property `[NotStored]` with the reason |

RS0030 comes from Microsoft.CodeAnalysis.BannedApiAnalyzers, which this package brings along together with its list of banned members. ABX1002 checks generated code as well; ABX1001 leaves it alone, because generators such as the gRPC tooling write regions of their own.

ABX1005 replaces Sonar's S1067, which also counts the `or` and `and` combinators of a pattern, taking the pattern as an expression of its own. S1067 is off unless a configuration raises it, so a project moving to this package removes the line that does. A pattern listing the cases one arm answers alike reads as a list rather than as conditions to combine, and counting it would force an exhaustive switch apart into arms that repeat one answer. An argument, a switch arm, a guard, an interpolation hole, a lambda body and each member an initializer sets are each judged as an expression of their own. Unlike S1067, the count goes on through a cast, a member access on a parenthesized expression, the null-forgiving `!` and `checked(...)`, since what they wrap is still read as part of the condition.

ABX1006 counts the summaries of each declared symbol across all its parts, so a partial type documented in two files is reported, a part a generator writes included; the finding is shown on the parts somebody edits, and a type a generator writes alone is left to it. It reads the documentation comments the compiler parses, which it does only in a project that generates a documentation file (`GenerateDocumentationFile`): elsewhere `///` is a plain comment and the rule has nothing to read.

ABX1007 and ABX1008 apply only where the compilation sees `[LoggerMessage]` and the two wrappers and two marks Abblix.Utils declares; elsewhere nothing is marked and the rules stay silent. An argument is followed back through the locals of its method - a copy, an assignment, a pattern, a `foreach` variable, an `out var` - and through interpolation, every constructor, and calls whose result can hold text, such as `Trim` or `string.Join`. A call returning anything else ends the trail, because what it returns is the server's own: the registered client found by a client id that was sent is not that client id. So does a constant, a flag, a number or an enum member, though not a single character, which can carry a line break: a record may say whether a code was sent, or how many scopes were, without wrapping anything. A method's parameter is not followed into its callers, so a value handed to a method is found only where that parameter carries a mark itself.

A mark sits on a type, not on where a value came from, and that has a price: a token the server issued itself is read through the same header and payload types as one it received, so its `jti` or `alg` is logged through `Sanitized` too. Sanitizing a value nobody chose costs nothing but the wrapper, which is cheaper than a rule that has to guess which token it is looking at.

ABX1003 and ABX1004 exist for the member somebody adds later. A conditional on one member sends it to the second branch, and a default arm answers for it, with nothing reported in either case. A switch that names every member stops compiling there instead. Both rules apply only to enums of your own product: declared in the assembly being built, or in one whose name starts with the same first segment, so `Contoso.Domain` counts for `Contoso.Web`. That holds the same in the IDE and in a build. The first segment names the vendor rather than one product, so `Contoso.Web` is also held to the rule for an enum of a separately shipped `Contoso.Messaging` package it references. An enum from anywhere else is exempt: there, dispatching on a few values and refusing the rest is the right shape, for example with a JSON token type. ABX1003 treats an ordering comparison (`>=`) and two member tests joined by `||` as picking by a member too. A `[Flags]` enum is exempt as well, because testing a bit is not choosing a member. A test for null or for a `bool` is never reported, since neither one can gain a value. A guarded arm (`when`) still counts as naming its member.

ABX1009 and ABX1010 apply only in the assembly that declares the OIDC server's codec, the one place its codecs are visible; a project that only references it, a test project included, is not checked. They are decided once the whole compilation is seen, so the build reports them rather than the editor as the code is typed. A storage call whose type is a type parameter is left to the caller that names the type. A written value is matched by a codec of its base type too, as the serializer matches it at run time; a value read back needs a codec of exactly the type named. A codec's mapper is the two delegates it is built from, followed into the static methods and constructors they call and on from there, but not into instance methods. Every field of a message the way out builds, a field being a property protoc writes a `FieldNumber` constant for, and every property of a type the way back builds that holds data, must be named in both directions; a positional parameter of a record counts for its property. Naming a member is all the rule asks, so a field filled from the wrong property passes: a round-trip test catches that.

## Use

The package is published to the Abblix GitHub feed (`https://nuget.pkg.github.com/Abblix/index.json`) by every dev build, from `develop` and from release branches, and is not part of a library release.

```xml
<PackageReference Include="Abblix.Analyzers" PrivateAssets="all" />
```

A project moving to this package deletes, in the same change, the copies of these rules it kept itself: the clock reads in its own `BannedSymbols.txt` (BannedApiAnalyzers refuses a member listed twice with RS0031), a StyleCop reference kept for SA1124, and any test that searched the sources for regions or clocks.

A rule a project really has to break is suppressed at the site, with the reason beside it.
