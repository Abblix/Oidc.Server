// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Thin endpoint-side adapter that delegates the RFC 9396 <c>authorization_details</c>
/// validation to <see cref="IAuthorizationDetailsPolicy.ApplyAsync"/> and converts the
/// returned error description to an
/// <see cref="AuthorizationRequestValidationError"/>. All actual policy lives on the
/// composite validator so /authorize, /par, CIBA and (future) device-flow endpoints share
/// one source of truth.
/// </summary>
public class AuthorizationDetailsRequestValidator(
    IAuthorizationDetailsPolicy policy) : IAuthorizationContextValidator
{
    /// <inheritdoc/>
    public async Task<AuthorizationRequestValidationError?> ValidateAsync(AuthorizationValidationContext context)
    {
        // Whether the request carried any, read before the call: the policy is handed this very
        // array, and a validator that narrows by editing in place empties it as it answers.
        var requested = context.Request.AuthorizationDetails is { Count: > 0 };

        var result = await policy.ApplyAsync(
            context.Request.AuthorizationDetails,
            context.ClientInfo,
            CancellationToken.None);

        if (!result.TryGetSuccess(out var validated))
            return context.InvalidAuthorizationDetails(result.GetFailure().ErrorDescription);

        if (validated.Count > 0)
            context.AuthorizationDetails = validated;
        else if (requested)
            throw AuthorizationDetailsPolicyContract.EveryEntryDropped();
        return null;
    }
}
