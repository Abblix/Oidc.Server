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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using TokenRequest = Abblix.Oidc.Server.Model.TokenRequest;

namespace Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

/// <summary>
/// Formats the result of a token request into an <see cref="IResult"/> (the success token response or the OAuth error).
/// </summary>
public interface ITokenResponseFormatter
{
    /// <summary>
    /// Formats the token endpoint result.
    /// </summary>
    /// <param name="request">The core token request being answered.</param>
    /// <param name="response">The success-or-error result produced by the token handler.</param>
    /// <returns>An <see cref="IResult"/> carrying the token response or the formatted error.</returns>
    Task<IResult> FormatResponseAsync(TokenRequest request, Result<TokenIssued, OidcError> response);
}
