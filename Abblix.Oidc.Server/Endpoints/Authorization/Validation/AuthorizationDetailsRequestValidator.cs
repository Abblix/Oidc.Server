// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.AuthorizationDetails;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates the RFC 9396 <c>authorization_details</c> array on an authorization request by
/// delegating to the shared <see cref="AuthorizationDetailsPolicy"/> (per-client allowlist
/// §5.1 + per-type composite dispatch §5). The validated raw array is stashed on the context
/// so downstream emitters (grant carriage, token response, introspection) see the
/// post-validation value.
/// </summary>
/// <param name="detailsValidator">The composite validator that dispatches each entry to its
/// keyed-by-<c>type</c> per-type implementation. Registered unconditionally by
/// <c>AddRichAuthorizationRequests</c>, so this dependency resolves on every deployment.
/// </param>
public class AuthorizationDetailsRequestValidator(
    IAuthorizationDetailsValidator detailsValidator) : IAuthorizationContextValidator
{
    /// <inheritdoc/>
    public async Task<AuthorizationRequestValidationError?> ValidateAsync(AuthorizationValidationContext context)
    {
        var result = await AuthorizationDetailsPolicy.ApplyAsync(
            context.Request.AuthorizationDetails,
            context.ClientInfo,
            detailsValidator);

        if (!result.TryGetSuccess(out var validated))
            return context.InvalidAuthorizationDetails(result.GetFailure());

        if (validated is not null)
            context.AuthorizationDetailsRaw = validated;
        return null;
    }
}
