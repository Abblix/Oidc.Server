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

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Represents a successful response for a client registration in the context of OpenID Connect.
/// Per RFC 7591 Section 3.2.1, the authorization server must return all registered metadata about the client.
/// </summary>
/// <remarks>
/// The response includes the client identifier, credentials, registration endpoint information,
/// and all registered client metadata. This allows the client to use the registration API
/// for subsequent operations on the client configuration.
/// </remarks>
/// <param name="ClientId">
/// A string representing the unique identifier assigned to the registered client.
/// Required per RFC 7591 Section 3.2.1.
/// </param>
/// <param name="ClientIdIssuedAt">
/// Time at which the client identifier was issued.
/// Optional per RFC 7591 Section 3.2.1.
/// </param>
/// <param name="RegistrationAccessToken">
/// The access token for subsequent operations on the client configuration endpoint.
/// Required per RFC 7592 Section 3 for accessing the client configuration endpoint.
/// </param>
public record ClientRegistrationSuccessResponse(
    string ClientId,
    DateTimeOffset? ClientIdIssuedAt,
    string RegistrationAccessToken)
{
    /// <summary>
    /// The client secret assigned to the registered client.
    /// Optional - only present for confidential clients. Per RFC 7591 Section 3.2.1.
    /// </summary>
    public string? ClientSecret { get; init; }

    /// <summary>
    /// The expiration time of the client secret.
    /// Required if client_secret is issued. Per RFC 7591 Section 3.2.1.
    /// A value of 0 indicates the secret does not expire.
    /// </summary>
    public DateTimeOffset? ClientSecretExpiresAt { get; init; }
}
