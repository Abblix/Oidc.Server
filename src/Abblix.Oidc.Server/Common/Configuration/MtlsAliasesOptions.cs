// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// The RFC 8705 mTLS endpoint aliases a tenant names itself in discovery. An alias left out is computed from the
/// tenant's mutual-TLS host, when it declares one.
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

