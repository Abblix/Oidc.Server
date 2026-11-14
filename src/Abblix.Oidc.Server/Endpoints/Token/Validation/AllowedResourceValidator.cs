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
/// Every resource the request names and every resource its grant holds is held to the list, so a resource taken off
/// the list refuses the next use of a grant holding it, whatever the request narrows the token to, and the grant does
/// not carry it on into a renewed refresh token. The access token is built from its grant
/// (<see cref="Token.TokenAuthorizationContextEvaluator"/>): the grant's resources narrowed to the ones the request
/// names, every one of them inside the grant (<see cref="GrantNarrowingValidator"/>), and when the request names none,
/// the grant holds none and names no audience, the tenant's default resource indicator
/// (<see cref="Common.AuthorizationContextExtensions.WithDefaultResource"/>), which is held too. Read once the grant
/// is authorized and before an authorization code or a refresh token is spent. The audiences a token exchange names
/// are held to the client's token exchange audiences instead.
/// </remarks>
public class AllowedResourceValidator : SyncTokenContextValidatorBase
{
    /// <inheritdoc />
    protected override OidcError? Validate(TenantDefinition tenant, TokenValidationContext context)
    {
        var named = context.Request.Resources ?? [];
        var grant = context.AuthorizedGrant.Context;

        Uri[] held = [.. named, .. grant.Resources ?? []];

        // The default reaches the token as it is built: when it would carry no resource and the grant names no audience,
        // since a token exchange carries the ones its request names into its grant and no other grant reads them off
        // the request
        if (held.Length == 0 &&
            grant.Audiences is not { Length: > 0 } &&
            tenant.DefaultResourceIndicator is { } defaultResource)
        {
            held = [defaultResource];
        }

        if (held.Any(resource => !context.ClientInfo.MayGetTokenFor(resource)))
            return new OidcError(ErrorCodes.InvalidTarget, ResourceRefusals.NotAllowedForClient);

        return null;
    }
}
