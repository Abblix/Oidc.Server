// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.AuthorizationDetails;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Validates the RFC 9396 §3 <c>authorization_details</c> array on a CIBA backchannel
/// authentication request by delegating to the shared <see cref="AuthorizationDetailsPolicy"/>
/// (per-client allowlist §5.1 + per-type composite dispatch §5). The validated raw array is
/// stored on the context so the downstream
/// <c>BackChannelAuthenticationRequestProcessor</c> can thread it onto the
/// <c>AuthorizationContext</c> for byte-exact emission on the issued access token.
/// </summary>
public class BackChannelAuthorizationDetailsValidator(
    IAuthorizationDetailsValidator detailsValidator) : IBackChannelAuthenticationContextValidator
{
    /// <inheritdoc/>
    public async Task<OidcError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
    {
        var result = await AuthorizationDetailsPolicy.ApplyAsync(
            context.Request.AuthorizationDetails,
            context.ClientInfo,
            detailsValidator);

        if (!result.TryGetSuccess(out var validated))
            return new OidcError(ErrorCodes.InvalidAuthorizationDetails, result.GetFailure());

        if (validated is not null)
            context.AuthorizationDetails = validated;
        return null;
    }
}
