// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents the response for a successful client read or update request: the client's credentials and every
/// metadata value the server holds for it, as RFC 7592 section 3 requires.
/// Unregistered metadata is omitted from the JSON per RFC 7592 section 3, not emitted as an explicit null.
/// </summary>
[JsonIgnoreNulls]
public record ReadClientSuccessfulResponse : RegisteredClientMetadata
{
    /// <summary>
    /// A response carrying no metadata yet, for a serializer reading one back.
    /// </summary>
    public ReadClientSuccessfulResponse()
    {
    }

    /// <summary>
    /// A response carrying <paramref name="metadata"/>, which the credentials are added to.
    /// </summary>
    public ReadClientSuccessfulResponse(RegisteredClientMetadata metadata)
        : base(metadata)
    {
    }

    /// <summary>
    /// The unique identifier of the client as registered with the authorization server.
    /// Required per RFC 7591 Section 3.2.1.
    /// </summary>
    [JsonPropertyOrder(1)]
    [JsonPropertyName(Parameters.ClientId)]
    public required string ClientId { get; init; }

    /// <summary>
    /// The secret associated with the client, used for authenticating with the authorization server.
    /// Optional - only present for confidential clients. Per RFC 7591 Section 3.2.1.
    /// </summary>
    [JsonPropertyOrder(2)]
    [JsonPropertyName(Parameters.ClientSecret)]
    public string? ClientSecret { get; init; }

    /// <summary>
    /// The expiration time of the client secret. Indicates when the client secret will become invalid.
    /// Required if client_secret is issued. Per RFC 7591 Section 3.2.1.
    /// A value of 0 indicates the secret does not expire.
    /// Serialized as Unix seconds (a JSON number) per RFC 7591 section 3.2.1, matching the register-path DTO.
    /// </summary>
    [JsonPropertyOrder(3)]
    [JsonPropertyName(Parameters.ClientSecretExpiresAt)]
    [JsonConverter(typeof(DateTimeOffsetUnixTimeSecondsConverter))]
    public DateTimeOffset? ClientSecretExpiresAt { get; init; }

    /// <summary>
    /// The fully qualified URL of the client configuration endpoint for this client.
    /// Required per RFC 7592 Section 3.
    /// </summary>
    [JsonPropertyOrder(4)]
    [JsonPropertyName(Parameters.RegistrationClientUri)]
    public Uri? RegistrationClientUri { get; init; }

    /// <summary>
    /// The access token for subsequent operations on the client configuration endpoint.
    /// Required per RFC 7592 Section 3.
    /// </summary>
    [JsonPropertyOrder(5)]
    [JsonPropertyName(Parameters.RegistrationAccessToken)]
    public required string RegistrationAccessToken { get; init; }

    /// <summary>
    /// Wire-level member names of the client read response that are not client metadata (RFC 7592 section 3,
    /// RFC 7591 section 3.2.1).
    /// </summary>
    private static class Parameters
    {
        /// <summary>The <c>client_id</c> response member carrying the client identifier.</summary>
        public const string ClientId = "client_id";

        /// <summary>The <c>client_secret</c> response member carrying the client secret.</summary>
        public const string ClientSecret = "client_secret";

        /// <summary>The <c>client_secret_expires_at</c> response member giving the secret expiration time;
        /// <c>0</c> means the secret does not expire.</summary>
        public const string ClientSecretExpiresAt = "client_secret_expires_at";

        /// <summary>The <c>registration_client_uri</c> response member (RFC 7592) locating the client
        /// configuration endpoint for this registration.</summary>
        public const string RegistrationClientUri = "registration_client_uri";

        /// <summary>The <c>registration_access_token</c> response member (RFC 7592) used to authorize
        /// subsequent operations on the client configuration endpoint.</summary>
        public const string RegistrationAccessToken = "registration_access_token";
    }
}
