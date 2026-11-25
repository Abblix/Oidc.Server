// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Counts the tokens each processed token request hands out into <see cref="OidcMetrics.TokensIssued"/>, and records
/// who was handed them in the log (<see cref="IssuedTokensLog"/>).
/// </summary>
/// <remarks>
/// Counted and recorded where the tokens are minted rather than where the token endpoint answers, because a CIBA push
/// delivery mints them without a request to that endpoint; and around every processor the token endpoint is built
/// from, a host's own and the one refusing a reused authorization code included, so what is counted and recorded is
/// the response as it is finally handed over.
/// </remarks>
/// <param name="logger">Records who was handed the tokens.</param>
/// <param name="fingerprints">Stands for the subject in that record.</param>
/// <param name="inner">The processor the server uses.</param>
/// <param name="instruments">Records the tokens into the server's metrics.</param>
/// <param name="grants">Tells the grant types the server supports, the only ones a measurement names.</param>
internal sealed class MeasuredTokenRequestProcessor(
    ILogger<MeasuredTokenRequestProcessor> logger,
    CredentialFingerprints fingerprints,
    ITokenRequestProcessor inner,
    OidcInstruments instruments,
    IAuthorizationGrantHandler grants) : ITokenRequestProcessor
{
    private readonly IssuedTokensLog _issuedTokens = new(logger, fingerprints);

    /// <inheritdoc />
    public async Task<Result<TokenIssued, OidcError>> ProcessAsync(TenantDefinition tenant, ValidTokenRequest request)
    {
        var result = await inner.ProcessAsync(tenant, request);
        if (result.TryGetSuccess(out var issued))
        {
            var grantType = EndpointObservation.GrantTypeOf(request.Model.GrantType, grants.GrantTypesSupported);
            instruments.TokenIssued(TelemetryTokenTypes.AccessToken, grantType, tenant.Id);
            if (issued.IdToken is not null)
                instruments.TokenIssued(TelemetryTokenTypes.IdToken, grantType, tenant.Id);
            if (issued.RefreshToken is not null)
                instruments.TokenIssued(TelemetryTokenTypes.RefreshToken, grantType, tenant.Id);

            _issuedTokens.AtTokenEndpoint(tenant, request, issued);
        }

        return result;
    }
}
