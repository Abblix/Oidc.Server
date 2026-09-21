// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Records the authentication levels a <c>claims</c> request requires of the ID token, so the endpoint can
/// honour them when it chooses a session.
/// </summary>
/// <remarks>
/// OpenID Connect Core 1.0 Section 5.5.1.1 states the obligation and the latitude together: when <c>acr</c>
/// is requested as an essential claim of the ID token with a <c>value</c> or <c>values</c> qualifier, the
/// server "MUST return an acr Claim Value that matches one of the requested values", it "MAY ask the End-User
/// to re-authenticate with additional factors to meet this requirement", and where the requirement cannot be
/// met it "MUST treat that outcome as a failed authentication attempt".
/// <para>
/// Recording the requirement here is what lets the endpoint take the latitude before the obligation: a
/// request no current session satisfies reaches the login page, which is the re-authentication the section
/// permits, and only a request that forbids interaction is refused outright. Reading it at the ID token
/// instead would leave the end user never asked.
/// </para>
/// <para>
/// Runs beside <see cref="RequestedSubjectValidator"/>, which reads the other claim of that parameter whose
/// own description imposes a condition, and inherits its placement: a refusal here is the kind RFC 6749
/// Section 4.1.2.1 says the client must be told about by redirection, and before the validators that resolve
/// the redirect URI there is nowhere to tell it.
/// </para>
/// </remarks>
public class RequiredAuthContextClassRefValidator : SyncAuthorizationContextValidatorBase
{
    /// <inheritdoc />
    protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
    {
        var required = context.Request.Claims.RequiredAuthContextClassRefs();
        if (required.TryGetFailure(out var reason))
            return context.InvalidRequest(reason);

        // An empty set means the request requires no particular level, said as the absence the filter reads.
        // An empty array would say the same thing there, because the filter checks its length - but then the
        // two would disagree about what an empty requirement is, and only one of them would be read.
        context.RequiredAuthContextClassRefs = required.GetSuccess() is { Length: > 0 } levels ? levels : null;
        return null;
    }
}
