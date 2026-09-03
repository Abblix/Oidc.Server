// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Common;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Thin endpoint-side adapter that delegates the RFC 9396 section 3 CIBA
/// <c>authorization_details</c> validation to
/// <see cref="IAuthorizationDetailsPolicy.ApplyAsync"/>. The composite already returns
/// an <see cref="OidcError"/> with <c>error = invalid_authorization_details</c>, so this
/// adapter just propagates it directly. All actual policy lives on the composite
/// validator so /authorize, /par, CIBA and (future) device-flow endpoints share one source
/// of truth.
/// </summary>
public class BackChannelAuthorizationDetailsValidator(
    IAuthorizationDetailsPolicy policy) : IBackChannelAuthenticationContextValidator
{
    /// <inheritdoc/>
    public async Task<OidcError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
    {
        var result = await policy.ApplyAsync(
            context.Request.AuthorizationDetails,
            context.ClientInfo,
            CancellationToken.None);

        if (!result.TryGetSuccess(out var validated))
            return result.GetFailure();

        if (validated is not null)
            context.AuthorizationDetails = validated;
        return null;
    }
}
