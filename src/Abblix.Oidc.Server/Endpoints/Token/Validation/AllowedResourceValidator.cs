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
/// Refuses a token request whose access token would be addressed to a resource the client may not get a token for
/// (<see cref="Features.ClientInformation.ClientInfo.AllowedResources"/>).
/// </summary>
/// <remarks>
/// The access token is built from its grant (<see cref="Token.TokenAuthorizationContextEvaluator"/>): the grant's
/// resources, narrowed to the ones the request names, else, with no resource and no audience in its grant, the
/// tenant's default resource indicator (<see cref="Common.AuthorizationContextExtensions.WithDefaultResource"/>).
/// Those are held to the list, and so is every resource the request names, as at every other endpoint, whether the
/// token carries it or not. Read once the grant is authorized and
/// before an authorization code or a refresh token is spent, and whenever a token is requested, so a resource taken
/// off the list is refused at the next use of a grant holding it. The audiences a token exchange names are held to
/// the client's token exchange audiences instead.
/// </remarks>
public class AllowedResourceValidator : SyncTokenContextValidatorBase
{
    /// <inheritdoc />
    protected override OidcError? Validate(TenantDefinition tenant, TokenValidationContext context)
    {
        var named = context.Request.Resources ?? [];
        var grant = context.AuthorizedGrant.Context;

        // As the token is built: the grant's resources narrowed to the named ones, and the grant's audiences, since a
        // token exchange carries the ones its request names into its grant and no other grant reads them off the request
        Uri[] carried = grant.Resources ?? [];
        if (carried.Length > 0 && named.Length > 0)
            carried = [.. carried.Intersect(named)];

        if (carried.Length == 0 &&
            grant.Audiences is not { Length: > 0 } &&
            tenant.DefaultResourceIndicator is { } defaultResource)
        {
            carried = [defaultResource];
        }

        if (named.Concat(carried).Any(resource => !context.ClientInfo.MayGetTokenFor(resource)))
            return new OidcError(ErrorCodes.InvalidTarget, ResourceRefusals.NotAllowedForClient);

        return null;
    }
}
