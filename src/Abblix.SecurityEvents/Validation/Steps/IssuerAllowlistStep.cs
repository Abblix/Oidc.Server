// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
/// Security-critical, because this step is also what keeps that unverified claim from steering
/// the key fetch: with the allowlist gone, a crafted "iss" aims the resolver's outbound request
/// at a network target of the sender's choosing, and the failed signature afterwards is no
/// consolation - the request itself was the prize.
/// </remarks>
public sealed class IssuerAllowlistStep : ISecurityCriticalValidator
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
