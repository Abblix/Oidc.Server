// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Formatter for responses to token revocation requests.
/// </summary>
/// <param name="issuerProvider">Supplies the issuer identifier used as the realm value on
/// <c>WWW-Authenticate</c> challenges for client-authentication failures.</param>
public class RevocationResponseFormatter(IIssuerProvider issuerProvider) : IRevocationResponseFormatter
{
    /// <summary>
    /// Asynchronously formats the response for a token revocation request.
    /// </summary>
    /// <remarks>
    /// This method handles different types of revocation responses and formats them
    /// into appropriate HTTP action results.
    /// </remarks>
    /// <param name="request">The token revocation request.</param>
    /// <param name="response">The response to the token revocation request.</param>
    /// <returns>
    /// A task that returns the formatted action result.
    /// </returns>
    public Task<ActionResult> FormatResponseAsync(RevocationRequest request, Result<TokenRevoked, OidcError> response)
    {
        return Task.FromResult(response.Match<ActionResult>(
            onSuccess: _ => new OkResult(),
            // RFC 7009 §2.2.1 defers to RFC 6749 §5.2 for error semantics, so the shared formatter
            // applies: invalid_client becomes a 401 with a Basic challenge, other errors stay 400.
            onFailure: error => error.Format(StatusCodes.Status400BadRequest, issuerProvider.GetIssuer())));
    }
}
