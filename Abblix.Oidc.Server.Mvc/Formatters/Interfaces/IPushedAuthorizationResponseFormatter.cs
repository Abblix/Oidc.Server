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

using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters.Interfaces;

/// <summary>
/// Defines the interface for formatting responses to pushed authorization requests.
/// </summary>
public interface IPushedAuthorizationResponseFormatter
{
    /// <summary>
    /// Formats the response to a pushed authorization request.
    /// </summary>
    /// <param name="request">The original authorization request.</param>
    /// <param name="response">The response from processing the authorization request,
    /// which could be a successful pushed authorization response or an error.</param>
    /// <returns>A task that resolves to an action result suitable for returning from an MVC action,
    /// representing the formatted response.</returns>
    Task<ActionResult> FormatResponseAsync(
        AuthorizationRequest request,
        Endpoints.Authorization.Interfaces.AuthorizationResponse response);
}
