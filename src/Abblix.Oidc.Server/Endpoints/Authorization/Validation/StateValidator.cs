// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Refuses, for a client whose security profile requires it, an authorization request naming no <c>openid</c> scope
/// and carrying no <c>state</c>. FAPI 1.0 Part 1 section 5.2.2.3, which Part 2 section 5.2.2 takes in: "If the client
/// does not requests the openid scope, the authorization server shall require the state parameter defined in Section
/// 4.1.1 of RFC6749".
/// </summary>
/// <remarks>
/// The scope judged is the one the client names, as the nonce rule judges it, so a request naming no scope is asked for
/// state whatever default it is served. RFC 6749 alone leaves state RECOMMENDED.
/// </remarks>
public class StateValidator : SyncAuthorizationContextValidatorBase
{
    /// <inheritdoc />
    protected override AuthorizationRequestValidationError? Validate(TenantDefinition tenant, AuthorizationValidationContext context)
    {
        if (string.IsNullOrEmpty(context.Request.State) &&
            SecurityProfileRequirements.For(context.ClientInfo, tenant.DefaultSecurityProfile).RequireStateWithoutOpenIdScope &&
            !context.ClientRequestsOpenId())
        {
            return context.InvalidRequest("The security profile requires state when the openid scope is not requested");
        }

        return null;
    }
}
