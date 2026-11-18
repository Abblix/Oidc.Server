// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ResourceIndicators;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Refuses a token request whose access token would name several resources, for a client whose access tokens each
/// name one (<see cref="Features.ClientInformation.ClientInfo.SingleResourceAccessTokens"/>).
/// </summary>
/// <remarks>
/// The access token names the resources the request names, else every resource of its grant, and its grant's
/// audiences, an audience equal to a declared resource counting as that resource (<see cref="ResourceScopes.AddressedBy"/>).
/// The audiences are the grant's because the token is built from it: a token exchange carries the ones its request
/// names into its grant, and no other grant reads them off the request. Read once the grant is
/// authorized and before an authorization code or a refresh token is spent, so a client refused here repeats the
/// request naming one resource. A device code or a backchannel request is spent while its grant is authorized, so
/// those grants are held to one resource at their own request.
/// </remarks>
public class SingleResourceValidator : SyncTokenContextValidatorBase
{
    /// <inheritdoc />
    protected override OidcError? Validate(TenantDefinition tenant, TokenValidationContext context)
    {
        if (!context.ClientInfo.SingleResourceAccessTokens)
            return null;

        var request = context.Request;
        var grant = context.AuthorizedGrant.Context;
        var addressed = ResourceScopes.AddressedBy(
            tenant,
            request.Resources is { Length: > 0 } named ? named : grant.Resources,
            grant.Audiences);

        if (addressed.Length > 1)
            return new OidcError(ErrorCodes.InvalidTarget, ResourceRefusals.OnePerAccessToken);

        return null;
    }
}
