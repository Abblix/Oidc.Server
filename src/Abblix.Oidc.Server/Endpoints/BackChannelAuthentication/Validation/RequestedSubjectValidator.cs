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
/// Refuses a <c>claims</c> request whose <c>sub</c> qualifier is not a string.
/// </summary>
/// <remarks>
/// This endpoint accepts the same <c>claims</c> parameter as the authorization endpoint and honours a
/// <c>sub</c> named in it the same way - OpenID Connect Core 1.0 Section 3.1.2.2 makes that and
/// <c>id_token_hint</c> two ways of stating one requirement. What differs is only where the comparison
/// happens, since the end user answers on a device long afterwards.
/// <para>
/// A malformed qualifier is refused here rather than left to the comparison, which would treat it as naming
/// nobody and answer as though the end user were simply unreachable. Section 5.5.1 requires the qualifier to
/// be "a valid value for the Claim being requested" and Section 2 makes <c>sub</c> a string, so a number or
/// an object is a request nobody could satisfy, and saying that outright is the difference between a client
/// fixing its request and a client retrying it.
/// </para>
/// </remarks>
public class RequestedSubjectValidator : IBackChannelAuthenticationContextValidator
{
    /// <inheritdoc />
    public Task<OidcError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
        => Task.FromResult(Validate(context));

    private static OidcError? Validate(BackChannelAuthenticationValidationContext context)
        => context.Request.Claims.RequestedSubjects().TryGetFailure(out var reason)
            ? new OidcError(ErrorCodes.InvalidRequest, reason)
            : null;
}
