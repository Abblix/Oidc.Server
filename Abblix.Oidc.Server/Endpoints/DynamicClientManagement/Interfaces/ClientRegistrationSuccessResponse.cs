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
/// </summary>
/// <param name="ClientId">A string representing the unique identifier assigned to the registered client.</param>
/// <param name="ClientIdIssuedAt">An optional DateTimeOffset indicating the time at which the client identifier was issued.</param>
public record ClientRegistrationSuccessResponse(string ClientId, DateTimeOffset? ClientIdIssuedAt)
{
    /// <summary>
    /// The client secret assigned to the registered client.
    /// </summary>
    public string? ClientSecret { get; init; }

    /// <summary>
    /// The expiration time of the client secret, if applicable.
    /// </summary>
    public DateTimeOffset? ClientSecretExpiresAt { get; init; }

    /// <summary>
    /// The registration access token associated with the client registration, if applicable.
    /// </summary>
    public string? RegistrationAccessToken { get; init; }
}
