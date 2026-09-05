// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt;
using Abblix.SecurityEvents.Validation;

namespace Abblix.SecurityEvents.BackChannelLogout.Steps;

/// <summary>
/// Accepts a Logout Token that carries no <c>typ</c>, and refuses one typed as something else.
/// </summary>
/// <remarks>
/// The step it replaces pins the SET's own type, and dropping that pin without putting one back
/// would leave the profile with no answer to cross-JWT confusion at the header at all. What it may
/// not do is demand the logout type. OpenID Connect Back-Channel Logout 1.0 Section 4.1 offers
/// explicit typing and rules out requiring it in the same breath: "Including an explicit type in
/// issued Logout Tokens is a best practice. Note however, that requiring explicitly typed Logout
/// Tokens will break most existing deployments, as existing OPs and RPs are already commonly using
/// untyped Logout Tokens." A receiver that required it would refuse conformant providers, so the
/// rule here is one-sided: an absent type is accepted, a foreign one is not.
/// <para>
/// Security-critical, because it stands where the profile's confusion wall at the header stands.
/// The wall it can build is lower than the SET's by the specification's own instruction, and the
/// claims the profile demands below - a logout event, no nonce, a subject or a session - are what
/// carry the rest of the weight.
/// </para>
/// </remarks>
public sealed class LogoutTokenTypeStep : ISecurityCriticalValidator
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(SecurityEventTokenValidationStates.Parsed);

        var type = context.UnverifiedHeader!.Type;

        SecurityEventTokenValidationError? error;
        if (type is null || JwtTypeName.Matches(type, JsonWebTokenTypes.LogoutToken))
        {
            context.Establish(SecurityEventTokenValidationStates.TypVerified);
            error = null;
        }
        else
        {
            error = new SecurityEventTokenValidationError(
                SecurityEventTokenErrorCode.TokenConfusion,
                $"A Logout Token carries '{JsonWebTokenTypes.LogoutToken}' or no type at all, not "
                + $"'{type}'.");
        }

        return ValueTask.FromResult(error);
    }
}
