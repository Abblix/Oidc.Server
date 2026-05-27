// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.AuthorizationDetails;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;

/// <summary>
/// Thin endpoint-side adapter that delegates the RFC 9396 §3 device-flow
/// <c>authorization_details</c> validation to
/// <see cref="IAuthorizationDetailsPolicy.ApplyAsync"/> and propagates the
/// <see cref="OidcError"/> as-is. All actual policy lives on the composite so /authorize,
/// /par, CIBA and device-flow endpoints share one source of truth.
/// </summary>
public class DeviceAuthorizationDetailsValidator(
    IAuthorizationDetailsPolicy policy) : IDeviceAuthorizationContextValidator
{
    /// <inheritdoc/>
    public async Task<OidcError?> ValidateAsync(DeviceAuthorizationValidationContext context)
    {
        var result = await policy.ApplyAsync(
            context.Request.AuthorizationDetails,
            context.ClientInfo);

        if (!result.TryGetSuccess(out var validated))
            return result.GetFailure();

        if (validated is not null)
            context.AuthorizationDetails = validated;
        return null;
    }
}
