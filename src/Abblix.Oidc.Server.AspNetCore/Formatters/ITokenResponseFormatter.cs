// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Utils;
using TokenRequest = Abblix.Oidc.Server.Model.TokenRequest;

namespace Abblix.Oidc.Server.AspNetCore.Formatters;

/// <summary>
/// Formats the result of a token request into a <typeparamref name="TResult"/> (the success token response or the OAuth error).
/// </summary>
/// <typeparam name="TResult">The transport's result type: an MVC action result or a Minimal API result.</typeparam>
public interface ITokenResponseFormatter<TResult> where TResult : class
{
    /// <summary>
    /// Formats the token endpoint result.
    /// </summary>
    /// <param name="request">The core token request being answered.</param>
    /// <param name="response">The success-or-error result produced by the token handler.</param>
    /// <returns>A <typeparamref name="TResult"/> carrying the token response or the formatted error.</returns>
    Task<TResult> FormatResponseAsync(TokenRequest request, Result<TokenIssued, OidcError> response);
}
