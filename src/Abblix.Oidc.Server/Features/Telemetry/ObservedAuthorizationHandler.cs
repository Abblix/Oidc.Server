// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <remarks>
/// The authorization endpoint's span names the request's response type, when the protocol defines each of its values,
/// and the tokens the endpoint hands out through the front channel are counted, and recorded in the log, under the
/// implicit grant, the grant OAuth names for them. Both read the response the handler answers with once it is encoded,
/// so a response the encoder turns into an error, as one whose response JWT cannot be built, neither counts nor is
/// recorded. The record is logged under the category of <see cref="AuthorizationHandler"/>.
/// </remarks>
internal sealed partial class ObservedAuthorizationHandler
{
    private IssuedTokensLog? _issuedTokens;

    private IssuedTokensLog IssuedTokens
        => _issuedTokens ??= new(_loggerFactory.CreateLogger<AuthorizationHandler>(), _credentialFingerprints);

    private partial (string Key, string? Value) RequestTagOf(TenantDefinition tenant, Model.AuthorizationRequest request)
        => (TelemetryTags.ResponseType, EndpointObservation.ResponseTypeOf(request.ResponseType));

    private partial void Observe(TenantDefinition tenant, Model.AuthorizationRequest request, AuthorizationResponse result)
    {
        if (result is not SuccessfullyAuthenticated authenticated)
            return;

        if (authenticated.AccessToken is not null)
            _instruments.TokenIssued(TelemetryTokenTypes.AccessToken, GrantTypes.Implicit, tenant.Id);
        if (authenticated.IdToken is not null)
            _instruments.TokenIssued(TelemetryTokenTypes.IdToken, GrantTypes.Implicit, tenant.Id);

        IssuedTokens.ThroughFrontChannel(tenant, authenticated);
    }
}
