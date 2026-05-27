// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Text.Json.Serialization;

namespace Abblix.Oidc.Server.E2E.Tests.Model;

/// <summary>
/// Typed projection of the /.well-known/openid-configuration document.
/// Only the members E2E tests actually read are declared; the rest of
/// the response is ignored by the deserialiser.
/// </summary>
public sealed record DiscoveryDocument
{
    [JsonPropertyName("issuer")]
    public string Issuer { get; init; } = null!;

    [JsonPropertyName("authorization_endpoint")]
    public string AuthorizationEndpoint { get; init; } = null!;

    [JsonPropertyName("token_endpoint")]
    public string TokenEndpoint { get; init; } = null!;

    [JsonPropertyName("registration_endpoint")]
    public string? RegistrationEndpoint { get; init; }

    [JsonPropertyName("pushed_authorization_request_endpoint")]
    public string? PushedAuthorizationRequestEndpoint { get; init; }

    [JsonPropertyName("introspection_endpoint")]
    public string? IntrospectionEndpoint { get; init; }

    [JsonPropertyName("jwks_uri")]
    public string JwksUri { get; init; } = null!;

    [JsonPropertyName("authorization_details_types_supported")]
    public string[]? AuthorizationDetailsTypesSupported { get; init; }
}
