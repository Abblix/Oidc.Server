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
