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

using System.Net.Http.Headers;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Validates the registration access token presented on calls to the client configuration
/// endpoint per RFC 7592 §3. Verifies the bearer token from the <c>Authorization</c> header
/// is bound to the requested <c>client_id</c>.
/// </summary>
public interface IRegistrationAccessTokenValidator
{
    /// <summary>
    /// Validates the bearer token, ensuring it is well-formed, of the expected type, and
    /// authorized to manage the specified client.
    /// </summary>
    /// <param name="header">The HTTP <c>Authorization</c> header carrying the bearer token.</param>
    /// <param name="clientId">The <c>client_id</c> targeted by the management request.</param>
    /// <returns>
    /// <c>null</c> when the token is valid for the client; otherwise a human-readable description
    /// of the validation failure.
    /// </returns>
    Task<string?> ValidateAsync(AuthenticationHeaderValue? header, string clientId);
}
