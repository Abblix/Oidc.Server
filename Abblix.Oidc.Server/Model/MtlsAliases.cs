// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Utils.Json;
using System.Text.Json.Serialization;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Discovery metadata block published as <c>mtls_endpoint_aliases</c> per RFC 8705 §5,
/// advertising alternate endpoint URLs that are served on a host configured for mutual TLS.
/// Clients performing certificate-bound authentication or requesting certificate-bound tokens
/// should target these aliases instead of the default endpoints exposed in
/// <see cref="ConfigurationResponse"/>.
/// Properties are omitted from the serialized JSON when null.
/// </summary>
[JsonIgnoreNulls]
public record MtlsAliases
{
    /// <summary>
    /// The mTLS-bound token endpoint URL (<c>token_endpoint</c>) used by clients authenticating
    /// with <c>tls_client_auth</c> or <c>self_signed_tls_client_auth</c>.
    /// </summary>
    [JsonPropertyName("token_endpoint")]
    public Uri? TokenEndpoint { get; init; }

    /// <summary>
    /// The mTLS-bound revocation endpoint URL (<c>revocation_endpoint</c>) per RFC 7009,
    /// reachable on the mTLS host so that revocation calls reuse the same client certificate.
    /// </summary>
    [JsonPropertyName("revocation_endpoint")]
    public Uri? RevocationEndpoint { get; init; }

    /// <summary>
    /// The mTLS-bound introspection endpoint URL (<c>introspection_endpoint</c>) per RFC 7662.
    /// </summary>
    [JsonPropertyName("introspection_endpoint")]
    public Uri? IntrospectionEndpoint { get; init; }

    /// <summary>
    /// The mTLS-bound UserInfo endpoint URL (<c>userinfo_endpoint</c>) used when access tokens
    /// are certificate-bound and must be presented over the same client certificate context.
    /// </summary>
    [JsonPropertyName("userinfo_endpoint")]
    public Uri? UserInfoEndpoint { get; init; }
}