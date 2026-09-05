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
