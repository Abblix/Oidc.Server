// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// The authorization endpoint's span names the request's response type, when the protocol defines each of its values,
/// and the tokens the endpoint hands out through the front channel are counted under the implicit grant, the grant
/// OAuth names for them.
/// </summary>
internal sealed partial class ObservedAuthorizationHandler
{
    private partial (string Key, string? Value) RequestTagOf(Model.AuthorizationRequest request)
        => (TelemetryTags.ResponseType, EndpointObservation.ResponseTypeOf(request.ResponseType));

    private partial void Observe(AuthorizationResponse result)
    {
        if (result is not SuccessfullyAuthenticated authenticated)
            return;

        var tenant = EndpointObservation.TenantOf(_tenants);
        if (authenticated.AccessToken is not null)
            _instruments.TokenIssued(TelemetryTokenTypes.AccessToken, GrantTypes.Implicit, tenant);
        if (authenticated.IdToken is not null)
            _instruments.TokenIssued(TelemetryTokenTypes.IdToken, GrantTypes.Implicit, tenant);
    }
}
