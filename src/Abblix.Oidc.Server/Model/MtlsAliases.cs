// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Discovery metadata block published as <c>mtls_endpoint_aliases</c> per RFC 8705 section 5,
/// advertising alternate endpoint URLs that are served on a host configured for mutual TLS.
/// Clients performing certificate-bound authentication or requesting certificate-bound tokens
/// should target these aliases instead of the default endpoints exposed in
/// <see cref="ConfigurationResponse"/>.
/// Properties are omitted from the serialized JSON when null.
/// </summary>
public record MtlsAliases
{
    /// <summary>
    /// The mTLS-bound token endpoint URL (<c>token_endpoint</c>) used by clients authenticating
    /// with <c>tls_client_auth</c> or <c>self_signed_tls_client_auth</c>.
    /// </summary>
    [JsonPropertyName(ConfigurationResponse.Parameters.TokenEndpoint)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? TokenEndpoint { get; init; }

    /// <summary>
    /// The mTLS-bound revocation endpoint URL (<c>revocation_endpoint</c>) per RFC 7009,
    /// reachable on the mTLS host so that revocation calls reuse the same client certificate.
    /// </summary>
    [JsonPropertyName(ConfigurationResponse.Parameters.RevocationEndpoint)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? RevocationEndpoint { get; init; }

    /// <summary>
    /// The mTLS-bound introspection endpoint URL (<c>introspection_endpoint</c>) per RFC 7662.
    /// </summary>
    [JsonPropertyName(ConfigurationResponse.Parameters.IntrospectionEndpoint)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? IntrospectionEndpoint { get; init; }

    /// <summary>
    /// The mTLS-bound UserInfo endpoint URL (<c>userinfo_endpoint</c>) used when access tokens
    /// are certificate-bound and must be presented over the same client certificate context.
    /// </summary>
    [JsonPropertyName(ConfigurationResponse.Parameters.UserInfoEndpoint)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? UserInfoEndpoint { get; init; }

    /// <summary>
    /// The mTLS-bound pushed authorization request endpoint URL (<c>pushed_authorization_request_endpoint</c>) per
    /// RFC 9126, where a client authenticating with its certificate pushes its request.
    /// </summary>
    [JsonPropertyName(ConfigurationResponse.Parameters.PushedAuthorizationRequestEndpoint)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? PushedAuthorizationRequestEndpoint { get; init; }

    /// <summary>
    /// The mTLS-bound backchannel authentication endpoint URL (<c>backchannel_authentication_endpoint</c>) of
    /// OpenID Connect CIBA, where a client authenticating with its certificate starts an authentication.
    /// </summary>
    [JsonPropertyName(ConfigurationResponse.Parameters.BackchannelAuthenticationEndpoint)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? BackChannelAuthenticationEndpoint { get; init; }

    /// <summary>
    /// The mTLS-bound device authorization endpoint URL (<c>device_authorization_endpoint</c>) per RFC 8628, where a
    /// client authenticating with its certificate starts a device authorization.
    /// </summary>
    [JsonPropertyName(ConfigurationResponse.Parameters.DeviceAuthorizationEndpoint)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? DeviceAuthorizationEndpoint { get; init; }
}