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
