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
using Microsoft.AspNetCore.Mvc;
using TokenRequest = Abblix.Oidc.Server.Model.TokenRequest;
using TokenResponse = Abblix.Oidc.Server.Model.TokenResponse;

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
        Result<TokenIssued, OidcError> response);
}
