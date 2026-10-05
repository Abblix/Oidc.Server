// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

// The tenant a span names is read from the multi-tenancy feature where it is in use
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Handles a request of the authorization endpoint in a span of <see cref="TelemetryEndpoints.Authorize"/>, and counts
/// the tokens it hands out through the front channel under the implicit grant, the grant OAuth names for them.
/// </summary>
/// <param name="inner">The handler of the endpoint.</param>
/// <param name="instruments">Records the request into the server's metrics.</param>
/// <param name="tenants">Tells the tenant serving the request, under multi-tenancy.</param>
internal sealed class TracedAuthorizationHandler(
    IAuthorizationHandler inner,
    OidcInstruments instruments,
    ITenantAccessor? tenants = null) : IAuthorizationHandler
{
    /// <inheritdoc />
    public async Task<Endpoints.Authorization.Interfaces.AuthorizationResponse> HandleAsync(Model.AuthorizationRequest request)
    {
        var response = await EndpointSpan.RunAsync(
            TelemetryEndpoints.Authorize,
            instruments,
            tenants,
            () => inner.HandleAsync(request),
            EndpointSpan.ErrorOf,
            () => (TelemetryTags.ResponseType, EndpointSpan.ResponseTypeOf(request.ResponseType)));

        if (response is SuccessfullyAuthenticated authenticated)
        {
            var tenant = EndpointSpan.TenantOf(tenants);
            if (authenticated.AccessToken is not null)
                instruments.TokenIssued(TelemetryTokenTypes.AccessToken, GrantTypes.Implicit, tenant);
            if (authenticated.IdToken is not null)
                instruments.TokenIssued(TelemetryTokenTypes.IdToken, GrantTypes.Implicit, tenant);
        }

        return response;
    }
}
