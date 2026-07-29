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
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using RevocationRequest = Abblix.Oidc.Server.Model.RevocationRequest;

using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats token revocation results as <see cref="IResult"/>: an empty 200 on success, or the RFC-compliant OAuth
/// error on failure.
/// </summary>
/// <param name="issuerProvider">Supplies the issuer used as the realm on client-authentication challenges.</param>
public class RevocationResponseFormatter(IIssuerProvider issuerProvider) : IRevocationResponseFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(RevocationRequest request, Result<TokenRevoked, OidcError> response)
        => Task.FromResult(FormatResponse(response));

    private IResult FormatResponse(Result<TokenRevoked, OidcError> response)
    {
        return response.Match(
            // RFC 7009 §2.2: a successful revocation returns 200 with an empty body.
            onSuccess: IResult (_) => Results.Ok(),

            // RFC 7009 §2.2.1 defers to RFC 6749 §5.2 for error semantics:
            // invalid_client -> 401 with a Basic challenge, other errors -> 400.
            onFailure: error => error.Format(StatusCodes.Status400BadRequest, issuerProvider.GetIssuer()));
    }
}
