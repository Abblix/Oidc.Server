; Unshipped analyzer releases
; https://github.com/dotnet/roslyn-analyzers/blob/main/src/Microsoft.CodeAnalysis.Analyzers/ReleaseTrackingAnalyzers.Help.md

### New Rules

Rule ID | Category | Severity | Notes
--------|----------|----------|-------
ABXT001 | Abblix.Oidc.Server.SourceGenerators.Telemetry | Error | An observed endpoint handler named by the assembly list is not an interface
ABXT002 | Abblix.Oidc.Server.SourceGenerators.Telemetry | Error | A member of an observed handler does not return a task of a result
ABXT003 | Abblix.Oidc.Server.SourceGenerators.Telemetry | Error | An observed result refuses with an error the endpoint observation cannot read
ABXT004 | Abblix.Oidc.Server.SourceGenerators.Telemetry | Error | A type the generator reads refusals by is not in the compilation
ABXT005 | Abblix.Oidc.Server.SourceGenerators.Telemetry | Error | Two entries of the list name the same decorator
ABXT006 | Abblix.Oidc.Server.SourceGenerators.Telemetry | Error | Hooks are asked for on a handler of more than one method
ABXT007 | Abblix.Oidc.Server.SourceGenerators.Telemetry | Error | A dependency's name is one the decorator already uses
