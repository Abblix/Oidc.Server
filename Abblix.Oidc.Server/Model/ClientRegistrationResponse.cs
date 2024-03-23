// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
    }

    /// <summary>
    /// The unique Client Identifier. It must not be currently valid for any other registered client.
    /// This identifier is critical for client identification and for securing client-to-server communication.
    /// </summary>
    [Required]
    [JsonPropertyName(Parameters.ClientId)]
    public string ClientId { get; init; } = default!;

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
}
