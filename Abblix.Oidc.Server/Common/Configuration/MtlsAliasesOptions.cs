// Abblix OIDC Server Library
// Copyright (c) Abblix LLP.

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Options for RFC 8705 mTLS endpoint aliases in discovery.
/// Allows explicitly setting alias URIs. Use DiscoveryOptions.MtlsBaseUri to auto-compute aliases.
/// </summary>
public class MtlsAliasesOptions
{
    public Uri? TokenEndpoint { get; set; }
    public Uri? RevocationEndpoint { get; set; }
    public Uri? IntrospectionEndpoint { get; set; }
    public Uri? UserInfoEndpoint { get; set; }
}

