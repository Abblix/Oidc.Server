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

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;

/// <summary>
/// Processes valid pushed authorization requests, generating a response that includes
/// the request's URI and its expiration.
/// </summary>
public interface IPushedAuthorizationRequestProcessor
{
    /// <summary>
    /// Asynchronously processes a valid authorization request and generates a response.
    /// </summary>
    /// <param name="request">The valid authorization request to process.</param>
    /// <returns>A task that resolves to an authorization response, including the
    /// request URI and expiration time.</returns>
    Task<AuthorizationResponse> ProcessAsync(ValidAuthorizationRequest request);
}
