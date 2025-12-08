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

using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents the client registration response as defined in the OpenID Connect specification.
/// </summary>
public record ClientRegistrationResponse
{
    private static class Parameters
    {
        public const string ClientId = "client_id";
        public const string ClientIdIssuedAt = "client_id_issued_at";

        public const string ClientSecret = "client_secret";
        public const string ClientSecretExpiresAt = "client_secret_expires_at";

        public const string RegistrationAccessToken = "registration_access_token";
        public const string RegistrationClientUri = "registration_client_uri";
        public const string InitiateLoginUri = "initiate_login_uri";
        public const string TokenEndpointAuthMethod = "token_endpoint_auth_method";
    }

    /// <summary>
    /// The unique Client Identifier. It must not be currently valid for any other registered client.
    /// This identifier is critical for client identification and for securing client-to-server communication.
    /// </summary>
    [Required]
    [JsonPropertyName(Parameters.ClientId)]
    public string ClientId { get; init; } = null!;

    /// <summary>
    /// The client secret. This value must not be assigned to multiple clients and is used for authenticating the client with the server.
    /// </summary>
    [JsonPropertyName(Parameters.ClientSecret)]
    public string? ClientSecret { get; init; }

    /// <summary>
    /// The registration access token that can be used at the Client Configuration Endpoint to perform subsequent operations on the client registration.
    /// </summary>
    [JsonPropertyName(Parameters.RegistrationAccessToken)]
    public string? RegistrationAccessToken { get; init; }

    /// <summary>
    /// The location of the Client Configuration Endpoint where the registration access token can be used for subsequent operations.
    /// </summary>
    [JsonPropertyName(Parameters.RegistrationClientUri)]
    public Uri? RegistrationClientUri { get; init; }

    /// <summary>
    /// The time at which the Client Identifier was issued. Represented as the number of seconds since Unix Epoch (1970-01-01T0:0:0Z) in UTC.
    /// </summary>
    [JsonPropertyName(Parameters.ClientIdIssuedAt)]
    [JsonConverter(typeof(DateTimeOffsetUnixTimeSecondsConverter))]
    public DateTimeOffset? ClientIdIssuedAt { get; init; }

    /// <summary>
    /// The time at which the client_secret will expire. Represented as the number of seconds since Unix Epoch (1970-01-01T0:0:0Z) in UTC.
    /// A value of 0 indicates that the secret does not expire.
    /// </summary>
    [Required]
    [JsonPropertyName(Parameters.ClientSecretExpiresAt)]
    [JsonConverter(typeof(DateTimeOffsetUnixTimeSecondsConverter))]
    public DateTimeOffset ClientSecretExpiresAt { get; init; }

    /// <summary>
    /// The URI for initiating the client's login process.
    /// </summary>
    [JsonPropertyName(Parameters.InitiateLoginUri)]
    public Uri? InitiateLoginUri { get; init; }

    /// <summary>
    /// The authentication method used by the client at the token endpoint.
    /// Possible values include "client_secret_basic", "client_secret_post", "client_secret_jwt",
    /// "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth", or "none".
    /// Per OpenID Connect Dynamic Client Registration Section 2.
    /// </summary>
    [JsonPropertyName(Parameters.TokenEndpointAuthMethod)]
    public string? TokenEndpointAuthMethod { get; init; }
}
