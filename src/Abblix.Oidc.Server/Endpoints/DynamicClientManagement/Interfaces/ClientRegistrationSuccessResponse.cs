// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Represents a successful response for a client registration in the context of OpenID Connect.
/// Per RFC 7591 section 3.2.1, the authorization server returns all registered metadata about the client
/// (including server-assigned defaults for omitted fields) so the client can confirm what was
/// registered without a separate read round-trip. The metadata is the same
/// <see cref="RegisteredClientMetadata"/> the read and update responses carry, differing only in
/// registration-specific timing (<see cref="ClientIdIssuedAt"/>) the read endpoint does not regenerate.
/// </summary>
/// <param name="ClientId">
/// The unique identifier assigned to the registered client. Required per RFC 7591 section 3.2.1.
/// </param>
/// <param name="ClientIdIssuedAt">
/// Time at which the client identifier was issued. Optional per RFC 7591 section 3.2.1.
/// </param>
/// <param name="RegistrationAccessToken">
/// The access token for subsequent operations on the client configuration endpoint.
/// Required per RFC 7592 section 3.
/// </param>
public record ClientRegistrationSuccessResponse(
    string ClientId,
    DateTimeOffset? ClientIdIssuedAt,
    string RegistrationAccessToken)
{
    /// <summary>
    /// The client secret assigned to the registered client.
    /// Optional - only present for confidential clients. Per RFC 7591 section 3.2.1.
    /// </summary>
    public string? ClientSecret { get; init; }

    /// <summary>
    /// The expiration time of the client secret.
    /// Required if <c>client_secret</c> is issued. Per RFC 7591 section 3.2.1.
    /// A value of 0 indicates the secret does not expire.
    /// </summary>
    public DateTimeOffset? ClientSecretExpiresAt { get; init; }

    /// <summary>
    /// The fully qualified URL of the client configuration endpoint for this client.
    /// Required per RFC 7592 section 3.
    /// </summary>
    [JsonPropertyName(ResponseParameters.RegistrationClientUri)]
    public Uri? RegistrationClientUri { get; init; }

    /// <summary>
    /// Every metadata value the server stored for the client, server-assigned defaults included.
    /// </summary>
    public required RegisteredClientMetadata Metadata { get; init; }

    /// <summary>
    /// JSON property names per RFC 7591/7592.
    /// </summary>
    private static class ResponseParameters
    {
        public const string RegistrationClientUri = "registration_client_uri";
    }
}
