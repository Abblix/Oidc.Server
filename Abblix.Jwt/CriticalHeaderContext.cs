namespace Abblix.Jwt;

/// <summary>
/// Per-call context passed to <see cref="ICriticalHeaderHandler.HandleAsync"/>.
/// Reference type with init-only properties so adding a future field is a
/// non-breaking change for handler implementations.
/// </summary>
public sealed class CriticalHeaderContext
{
    /// <summary>The parsed JWS being validated. Handlers typically read
    /// <c>Token.Header.Json[name]</c> for their declared name; payload access
    /// is available when the extension's semantics span both halves
    /// (e.g. RFC 8225 PASSporT profile rules).</summary>
    public required JsonWebToken Token { get; init; }

    /// <summary>The host-supplied validation parameters in force for this
    /// call. Handlers consult these to honour caller policy (algorithm
    /// allowlists, time skew, audience/issuer hooks).</summary>
    public required ValidationParameters Parameters { get; init; }
}