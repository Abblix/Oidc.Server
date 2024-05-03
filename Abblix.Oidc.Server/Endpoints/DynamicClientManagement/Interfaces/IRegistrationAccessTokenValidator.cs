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
/// Provides an interface for validating registration access tokens.
/// </summary>
public interface IRegistrationAccessTokenValidator
{
    /// <summary>
    /// Validates the registration access token asynchronously.
    /// </summary>
    /// <param name="header">The authentication header containing the token.</param>
    /// <param name="clientId">The client ID associated with the token.</param>
    /// <returns>A task representing the asynchronous operation. The task result contains the validation result (token or null).</returns>
    Task<string?> ValidateAsync(AuthenticationHeaderValue? header, string clientId);
}
