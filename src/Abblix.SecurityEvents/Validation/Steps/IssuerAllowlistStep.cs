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

namespace Abblix.SecurityEvents.Validation.Steps;

/// <summary>
/// Requires the "iss" claim to name an issuer this receiver accepts events from. The claim is
/// REQUIRED (RFC 8417 Section 2.2), and running the check before the signature step keeps an
/// unknown issuer's token from costing a key resolution: the signature step's resolver would
/// refuse it anyway, but refusing here names the reason precisely.
/// </summary>
/// <remarks>
/// The issuer read here is unverified - it decides only whether to PROCEED, and proceeding means
/// verifying a signature against that issuer's keys, so a lie about "iss" buys an attacker
/// nothing: the signature against the claimed issuer's keys is exactly what fails next.
/// </remarks>
public sealed class IssuerAllowlistStep : ISecurityEventTokenValidationStep
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(SecurityEventTokenValidationStates.Parsed);

        var issuer = context.UnverifiedPayload!.Issuer;

        SecurityEventTokenValidationError? error;
        if (string.IsNullOrEmpty(issuer))
        {
            error = new SecurityEventTokenValidationError(
                SecurityEventTokenErrorCode.UnknownIssuer,
                $"The claims carry no '{JwtClaimTypes.Issuer}' member (RFC 8417 Section 2.2).");
        }
        else if (!context.Options.ExpectedIssuers.Contains(issuer))
        {
            error = new SecurityEventTokenValidationError(
                SecurityEventTokenErrorCode.UnknownIssuer,
                $"This receiver accepts no events from '{issuer}'.");
        }
        else
        {
            context.Establish(SecurityEventTokenValidationStates.IssuerAccepted);
            error = null;
        }

        return ValueTask.FromResult(error);
    }
}
