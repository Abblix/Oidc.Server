// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Model;


namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Reads the authentication levels an essential <c>acr</c> in the <c>claims</c> parameter requires, and
/// refuses a request whose qualifiers no authentication could satisfy.
/// </summary>
/// <remarks>
/// OpenID Connect Core 1.0 Section 5.5.1.1 makes an essential <c>acr</c> that cannot be met a failed
/// authentication attempt. Nobody has authenticated yet when the request arrives, so the level itself is
/// judged at completion; what can be decided here is only whether the requirement is one any level could
/// meet, and saying so now spares an end user a device prompt that could never succeed. The levels are then
/// handed to the host, which chooses how the end user authenticates and is the only party able to meet them.
/// <para>
/// <c>acr_values</c> is not read here. CIBA Core 1.0 Section 7.1 describes it as the values the provider
/// "is being requested to use", with the means of authenticating "ultimately at the discretion of the OP",
/// so it stays a preference the host reads from the request rather than a condition this server enforces.
/// </para>
/// </remarks>
public class RequiredAuthContextClassRefValidator : IBackChannelAuthenticationContextValidator
{
    /// <inheritdoc />
    public Task<OidcError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
        => Task.FromResult(Validate(context));

    private static OidcError? Validate(BackChannelAuthenticationValidationContext context)
    {
        var required = context.Request.Claims.RequiredAuthContextClassRefs();
        if (required.TryGetFailure(out var reason))
            return new OidcError(ErrorCodes.InvalidRequest, reason);

        // An empty set means the request requires no particular level, said as the absence the host reads.
        context.RequiredAuthContextClassRefs = required.GetSuccess() is { Length: > 0 } levels ? levels : null;
        return null;
    }
}
