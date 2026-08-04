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

using Abblix.SecurityEvents.Validation;

namespace Abblix.SharedSignals.Receiver;

/// <summary>
/// Binds each event to the stream it arrived on: the "iss" claim must equal the Stream
/// Configuration's issuer (SSF 1.0 Section 4.1.6). Without this binding a token from any trusted
/// issuer would be accepted on any stream, and events could be replayed across streams whose
/// issuers differ.
/// </summary>
/// <remarks>
/// Section 4.1.6 names two values to match - the Stream Configuration's "iss" and the issuer
/// the Transmitter Configuration was requested from. The receiver proved those equal when it
/// accepted the stream (Sections 7.2.2, 8.1.1.1), so the single comparison here carries both
/// halves of the rule; see <see cref="SsfValidationOptions.StreamIssuer"/>.
/// </remarks>
public sealed class StreamIssuerStep : ISecurityCriticalValidator
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(SecurityEventTokenValidationStates.SignatureVerified);

        // A missing expectation is a configuration bug, not a token defect: without the stream's
        // issuer there is nothing to bind the event to, and reporting that as a token error would
        // blame every token for the receiver's wiring.
        if (context.Options is not SsfValidationOptions { StreamIssuer: { Length: > 0 } streamIssuer })
        {
            throw new InvalidOperationException(
                $"{nameof(StreamIssuerStep)} requires {nameof(SsfValidationOptions)}."
                + $"{nameof(SsfValidationOptions.StreamIssuer)} to be configured with the issuer from the "
                + "stream's configuration (SSF 1.0 Section 4.1.6).");
        }

        var error = string.Equals(context.Token!.Issuer, streamIssuer, StringComparison.Ordinal)
            ? null
            : new SecurityEventTokenValidationError(
                SecurityEventTokenErrorCode.UnknownIssuer,
                $"The 'iss' claim '{context.Token.Issuer}' does not match the stream configuration's "
                + $"issuer '{streamIssuer}' (SSF 1.0 Section 4.1.6).");

        return ValueTask.FromResult(error);
    }
}
