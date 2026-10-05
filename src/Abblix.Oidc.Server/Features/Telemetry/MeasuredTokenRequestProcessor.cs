// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

// The tenant a measurement names is read from the multi-tenancy feature where it is in use
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Counts the tokens each processed token request hands out into <see cref="OidcMetrics.TokensIssued"/>.
/// </summary>
/// <remarks>
/// Counted where the tokens are minted rather than where the token endpoint answers, because a CIBA push delivery
/// mints them without a request to that endpoint.
/// </remarks>
/// <param name="inner">The processor the server uses.</param>
/// <param name="instruments">Records the tokens into the server's metrics.</param>
/// <param name="tenants">Tells the tenant serving the request, under multi-tenancy.</param>
internal sealed class MeasuredTokenRequestProcessor(
    ITokenRequestProcessor inner,
    OidcInstruments instruments,
    ITenantAccessor? tenants = null) : ITokenRequestProcessor
{
    /// <inheritdoc />
    public async Task<Result<TokenIssued, OidcError>> ProcessAsync(ValidTokenRequest request)
    {
        var result = await inner.ProcessAsync(request);
        if (result.TryGetSuccess(out var issued))
        {
            // A validated request carries a grant type the server handled, so it is one of the server's own
            var grantType = request.Model.GrantType;
            var tenant = EndpointSpan.TenantOf(tenants);
            instruments.TokenIssued(TelemetryTokenTypes.AccessToken, grantType, tenant);
            if (issued.IdToken is not null)
                instruments.TokenIssued(TelemetryTokenTypes.IdToken, grantType, tenant);
            if (issued.RefreshToken is not null)
                instruments.TokenIssued(TelemetryTokenTypes.RefreshToken, grantType, tenant);
        }

        return result;
    }
}
