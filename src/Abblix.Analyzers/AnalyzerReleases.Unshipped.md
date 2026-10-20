; Unshipped analyzer releases
; https://github.com/dotnet/roslyn-analyzers/blob/main/src/Microsoft.CodeAnalysis.Analyzers/ReleaseTrackingAnalyzers.Help.md

### New Rules

Rule ID | Category | Severity | Notes
--------|----------|----------|-------
ABX1001 | Abblix.Conventions | Error | A #region hides code
ABX1002 | Abblix.Conventions | Error | A type declares its own TimeProvider
ABX1003 | Abblix.Conventions | Error | A conditional expression picks by one member of an enum
ABX1004 | Abblix.Conventions | Error | A switch on an enum leaves members to the default
ABX1005 | Abblix.Conventions | Error | An expression joins too many conditions
ABX1006 | Abblix.Conventions | Error | A declaration has more than one summary
ABX1007 | Abblix.Conventions | Error | A value from outside reaches the log unsanitized
ABX1008 | Abblix.Conventions | Error | A credential reaches the log other than as its fingerprint
ABX1009 | Abblix.Conventions | Error | A stored type has no protobuf codec
ABX1010 | Abblix.Conventions | Error | A stored member is mapped in one direction only, or in none
