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
using Abblix.Oidc.Server.Features.ScopeManagement;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Holds a token request to narrowing its grant: a resource it names that the grant does not hold refuses it
/// (RFC 8707 section 2.2), rather than a token being issued without that resource, and so does a scope naming none
/// of the granted scopes.
/// </summary>
/// <remarks>
/// Read once the grant is authorized and before an authorization code is spent, so a client refused here corrects
/// the request and redeems the code. A device code or a backchannel request is spent while its grant is authorized,
/// so for those grants the refusal ends the flow.
/// </remarks>
public class GrantNarrowingValidator : SyncTokenContextValidatorBase
{
    /// <inheritdoc />
    protected override OidcError? Validate(TenantDefinition tenant, TokenValidationContext context)
    {
        var grant = context.AuthorizedGrant.Context;

        // A scope partly outside the grant is narrowed to the granted ones, which the response reports in its scope
        if (context.Scope.Length > 0 &&
            !grant.Scope.Intersect(from definition in context.Scope select definition.Scope, StringComparer.Ordinal).Any())
        {
            return new OidcError(ErrorCodes.InvalidScope, ScopeRefusals.NotGranted);
        }

        if (context.Resources.Any(definition => grant.Resources?.Contains(definition.Resource) != true))
            return new OidcError(ErrorCodes.InvalidTarget, ResourceRefusals.NotGranted);

        return null;
    }
}
