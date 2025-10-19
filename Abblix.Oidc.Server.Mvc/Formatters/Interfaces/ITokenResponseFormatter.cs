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

using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Mvc.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;
using TokenRequest = Abblix.Oidc.Server.Model.TokenRequest;

namespace Abblix.Oidc.Server.Mvc.Formatters.Interfaces;

/// <summary>
/// Defines an interface for formatting an OAuth 2.0 token response as a low-level response object to return to the client.
/// </summary>
public interface ITokenResponseFormatter
{
    /// <summary>
    /// Formats an OAuth 2.0 token response asynchronously as a low-level response object to return to the client.
    /// </summary>
    /// <param name="request">The token request.</param>
    /// <param name="response">The token response to be formatted.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation, with the formatted response as an <see cref="ActionResult{TValue}"/> containing a <see cref="TokenResponse"/>.</returns>
    Task<ActionResult<TokenResponse>> FormatResponseAsync(TokenRequest request,
        Result<TokenIssued, TokenError> response);
}
