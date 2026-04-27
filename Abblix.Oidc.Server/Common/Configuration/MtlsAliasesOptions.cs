// Abblix OIDC Server Library
// Copyright (c) Abblix LLP.

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Options for RFC 8705 mTLS endpoint aliases in discovery.
/// Allows explicitly setting alias URIs. Use DiscoveryOptions.MtlsBaseUri to auto-compute aliases.
/// </summary>
public class MtlsAliasesOptions
{
    /// <summary>
    /// Mutual-TLS alias for the token endpoint, advertised in discovery as
    /// <c>mtls_endpoint_aliases.token_endpoint</c>. Clients that authenticate via certificate-bound
    /// access tokens are expected to use this URI instead of the regular token endpoint.
    /// </summary>
    public Uri? TokenEndpoint { get; set; }

    /// <summary>
    /// Mutual-TLS alias for the revocation endpoint, advertised in discovery as
    /// <c>mtls_endpoint_aliases.revocation_endpoint</c>.
    /// </summary>
    public Uri? RevocationEndpoint { get; set; }

    /// <summary>
    /// Mutual-TLS alias for the introspection endpoint, advertised in discovery as
    /// <c>mtls_endpoint_aliases.introspection_endpoint</c>.
    /// </summary>
    public Uri? IntrospectionEndpoint { get; set; }

    /// <summary>
    /// Mutual-TLS alias for the userinfo endpoint, advertised in discovery as
    /// <c>mtls_endpoint_aliases.userinfo_endpoint</c>.
    /// </summary>
    public Uri? UserInfoEndpoint { get; set; }
}

