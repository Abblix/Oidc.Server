// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.AuthorizationDetails;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Thin endpoint-side adapter that delegates the RFC 9396 §3 CIBA
/// <c>authorization_details</c> validation to
/// <see cref="IAuthorizationDetailsValidator.ApplyAsync"/> and converts the returned error
/// description to an <see cref="OidcError"/>. All actual policy lives on the composite
/// validator so /authorize, /par, CIBA and (future) device-flow endpoints share one source
/// of truth.
/// </summary>
public class BackChannelAuthorizationDetailsValidator(
    IAuthorizationDetailsValidator detailsValidator) : IBackChannelAuthenticationContextValidator
{
    /// <inheritdoc/>
    public async Task<OidcError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
    {
        var result = await detailsValidator.ApplyAsync(
            context.Request.AuthorizationDetails,
            context.ClientInfo);

        if (!result.TryGetSuccess(out var validated))
            return new OidcError(ErrorCodes.InvalidAuthorizationDetails, result.GetFailure());

        if (validated is not null)
            context.AuthorizationDetails = validated;
        return null;
    }
}
