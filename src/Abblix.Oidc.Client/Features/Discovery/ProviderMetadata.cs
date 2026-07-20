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

using System.Text.Json.Serialization;

namespace Abblix.Oidc.Client.Features.Discovery;

/// <summary>
/// The OpenID Provider metadata document published at <c>/.well-known/openid-configuration</c>,
/// as defined by OpenID Connect Discovery 1.0 and RFC 8414.
/// </summary>
/// <remarks>
/// Property names are pinned with <see cref="JsonPropertyNameAttribute"/> rather than derived from a naming
/// policy: this document is produced by a foreign provider, so its wire names must not depend on how the
/// host happens to configure its serializer.
///
/// Only the members the client actually acts upon are modelled. A provider is free to publish members this
/// client does not know, and doing so must not break deserialization, so unmapped members are preserved in
/// <see cref="AdditionalMetadata"/> instead of being discarded.
/// </remarks>
public sealed record ProviderMetadata
{
    /// <summary>
    /// The provider's issuer identifier. Every token this client accepts must name this issuer, and the value
    /// is verified against the address the document was fetched from.
    /// </summary>
    [JsonPropertyName("issuer")]
    public required string Issuer { get; init; }

    /// <summary>
    /// The authorization endpoint the user agent is redirected to at the start of the flow.
    /// </summary>
    [JsonPropertyName("authorization_endpoint")]
    public string? AuthorizationEndpoint { get; init; }

    /// <summary>
    /// The token endpoint used to exchange an authorization code and to refresh tokens.
    /// </summary>
    [JsonPropertyName("token_endpoint")]
    public string? TokenEndpoint { get; init; }

    /// <summary>
    /// The endpoint publishing the provider's JSON Web Key Set, the source of the keys that verify token
    /// signatures.
    /// </summary>
    [JsonPropertyName("jwks_uri")]
    public string? JsonWebKeySetUri { get; init; }

    /// <summary>
    /// The endpoint returning claims about the authenticated user.
    /// </summary>
    [JsonPropertyName("userinfo_endpoint")]
    public string? UserInfoEndpoint { get; init; }

    /// <summary>
    /// The endpoint that terminates the provider-side session for RP-initiated logout.
    /// </summary>
    [JsonPropertyName("end_session_endpoint")]
    public string? EndSessionEndpoint { get; init; }

    /// <summary>
    /// The endpoint that revokes an issued token, per RFC 7009.
    /// </summary>
    [JsonPropertyName("revocation_endpoint")]
    public string? RevocationEndpoint { get; init; }

    /// <summary>
    /// The PKCE code challenge methods the provider supports. Absence is meaningful: a provider that does not
    /// advertise <c>S256</c> cannot be assumed to support it.
    /// </summary>
    [JsonPropertyName("code_challenge_methods_supported")]
    public IReadOnlyList<string>? CodeChallengeMethodsSupported { get; init; }

    /// <summary>
    /// The signing algorithms the provider may use for an <c>id_token</c>.
    /// </summary>
    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public IReadOnlyList<string>? IdTokenSigningAlgValuesSupported { get; init; }

    /// <summary>
    /// Indicates whether the provider returns the <c>iss</c> parameter in the authorization response,
    /// the mix-up defence of RFC 9207.
    /// </summary>
    [JsonPropertyName("authorization_response_iss_parameter_supported")]
    public bool? AuthorizationResponseIssParameterSupported { get; init; }

    /// <summary>
    /// Members of the document this client does not model, kept verbatim so that a paid layer or a host can
    /// read a provider capability the base client has no opinion about.
    /// </summary>
    [JsonExtensionData]
    public IDictionary<string, object?>? AdditionalMetadata { get; init; }
}
