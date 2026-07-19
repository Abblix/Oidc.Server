// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Text.Json.Serialization;

namespace Abblix.Oidc.Server.E2E.Tests.Model;

/// <summary>
/// Typed projection of the /.well-known/openid-configuration document.
/// Only the members E2E tests actually read are declared; the rest of
/// the response is ignored by the deserialiser. Every URL-bearing field
/// surfaces as <see cref="Uri"/> so a malformed wire value fails at JSON
/// parse time, not at the first <c>HttpClient.SendAsync</c> call, and so
/// callers do not sprinkle <c>new Uri(...)</c> wraps over discovery reads.
/// </summary>
public sealed record DiscoveryDocument
{
    [JsonPropertyName("issuer")]
    public Uri Issuer { get; init; } = null!;

    [JsonPropertyName("authorization_endpoint")]
    public Uri AuthorizationEndpoint { get; init; } = null!;

    [JsonPropertyName("token_endpoint")]
    public Uri TokenEndpoint { get; init; } = null!;

    [JsonPropertyName("registration_endpoint")]
    public Uri? RegistrationEndpoint { get; init; }

    [JsonPropertyName("pushed_authorization_request_endpoint")]
    public Uri? PushedAuthorizationRequestEndpoint { get; init; }

    [JsonPropertyName("introspection_endpoint")]
    public Uri? IntrospectionEndpoint { get; init; }

    [JsonPropertyName("userinfo_endpoint")]
    public Uri? UserInfoEndpoint { get; init; }

    [JsonPropertyName("jwks_uri")]
    public Uri JwksUri { get; init; } = null!;

    [JsonPropertyName("authorization_details_types_supported")]
    public string[]? AuthorizationDetailsTypesSupported { get; init; }

    [JsonPropertyName("grant_types_supported")]
    public string[]? GrantTypesSupported { get; init; }

    /// <summary>RFC 9449 §5.1: JWS algorithms the AS accepts for DPoP proofs.</summary>
    [JsonPropertyName("dpop_signing_alg_values_supported")]
    public string[]? DPoPSigningAlgValuesSupported { get; init; }

    /// <summary>RFC 9701 §7: JWS algorithms the AS uses to sign JWT introspection responses.</summary>
    [JsonPropertyName("introspection_signing_alg_values_supported")]
    public string[]? IntrospectionSigningAlgValuesSupported { get; init; }
}
