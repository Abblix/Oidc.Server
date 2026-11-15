// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// The registration pipeline's step judging the initial access token through <see cref="IInitialAccessTokenValidator"/>,
/// the one judge a host that refuses a request by its token before reading the body asks too. Skipped for updates,
/// which the registration access token authorizes.
/// </summary>
/// <param name="validator">Judges the initial access token.</param>
public class InitialAccessTokenContextValidator(IInitialAccessTokenValidator validator) : IClientRegistrationContextValidator
{
    /// <inheritdoc />
    public Task<OidcError?> ValidateAsync(TenantDefinition tenant, ClientRegistrationValidationContext context)
        => context.Operation switch
        {
            DynamicClientOperation.Register => validator.ValidateAsync(tenant, context.Request.AuthorizationHeaderLines),
            DynamicClientOperation.Update => Task.FromResult<OidcError?>(null),
            _ => throw new ArgumentOutOfRangeException(
                nameof(context), context.Operation, "The registration operation is unknown"),
        };
}
