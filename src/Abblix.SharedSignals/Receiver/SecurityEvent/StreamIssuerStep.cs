// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Validation;

namespace Abblix.SharedSignals.Receiver.SecurityEvent;

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
/// halves of the rule; see <see cref="SharedSignalsValidationOptions.StreamIssuer"/>.
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
        if (context.Options is not SharedSignalsValidationOptions { StreamIssuer: { Length: > 0 } streamIssuer })
        {
            throw new InvalidOperationException(
                $"{nameof(StreamIssuerStep)} requires {nameof(SharedSignalsValidationOptions)}."
                + $"{nameof(SharedSignalsValidationOptions.StreamIssuer)} to be configured with the issuer from the "
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
