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
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

// The tenant a span names is read from the multi-tenancy feature where it is in use
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Handles a request of the token endpoint in a span of <see cref="TelemetryEndpoints.Token"/>, and counts the tokens
/// it hands out.
/// </summary>
/// <param name="inner">The handler of the endpoint.</param>
/// <param name="grants">Tells the grant types the server supports, the only ones a span or a measurement names.</param>
/// <param name="instruments">Records the request into the server's metrics.</param>
/// <param name="tenants">Tells the tenant serving the request, under multi-tenancy.</param>
internal sealed class TracedTokenHandler(
    ITokenHandler inner,
    IAuthorizationGrantHandler grants,
    OidcInstruments instruments,
    ITenantAccessor? tenants = null) : ITokenHandler
{
    /// <inheritdoc />
    public async Task<Result<TokenIssued, OidcError>> HandleAsync(TokenRequest tokenRequest, ClientRequest clientRequest, CancellationToken cancellationToken)
    {
        var result = await EndpointSpan.RunAsync(
            TelemetryEndpoints.Token,
            instruments,
            tenants,
            () => inner.HandleAsync(tokenRequest, clientRequest, cancellationToken),
            EndpointSpan.ErrorOf,
            () => (TelemetryTags.GrantType, GrantTypeOf(tokenRequest)));

        if (result.TryGetSuccess(out var issued))
        {
            var grantType = GrantTypeOf(tokenRequest);
            var tenant = EndpointSpan.TenantOf(tenants);
            instruments.TokenIssued(TelemetryTokenTypes.AccessToken, grantType, tenant);
            if (issued.IdToken is not null)
                instruments.TokenIssued(TelemetryTokenTypes.IdToken, grantType, tenant);
            if (issued.RefreshToken is not null)
                instruments.TokenIssued(TelemetryTokenTypes.RefreshToken, grantType, tenant);
        }

        return result;
    }

    /// <summary>
    /// The grant type of the request when the server supports it, so a client cannot put a value of its own on a
    /// span or a measurement.
    /// </summary>
    private string? GrantTypeOf(TokenRequest tokenRequest)
        => grants.GrantTypesSupported.Contains(tokenRequest.GrantType, StringComparer.Ordinal)
            ? tokenRequest.GrantType
            : null;
}
