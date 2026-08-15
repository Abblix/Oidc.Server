// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
