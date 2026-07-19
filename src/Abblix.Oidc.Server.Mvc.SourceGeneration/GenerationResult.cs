namespace Abblix.Oidc.Server.Mvc.SourceGeneration;

/// <summary>
/// The rendered output for one model: the hint name, the full source text (or null when generation
/// failed), and the diagnostics to report. A pure value so the driver skips re-emission when
/// nothing changed.
/// </summary>
internal sealed record GenerationResult(
    string HintName,
    string? Source,
    EquatableArray<DiagnosticInfo> Diagnostics);