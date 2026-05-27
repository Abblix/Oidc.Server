// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

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
        var result = await policy.ApplyAsync(
            context.Request.AuthorizationDetails,
            context.ClientInfo);

        if (!result.TryGetSuccess(out var validated))
            return context.InvalidAuthorizationDetails(result.GetFailure().ErrorDescription);

        if (validated is not null)
            context.AuthorizationDetailsRaw = validated;
        return null;
    }
}
