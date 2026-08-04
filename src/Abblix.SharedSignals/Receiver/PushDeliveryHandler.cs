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

using System.Net.Http.Headers;
using Abblix.Jwt.ReplayPrevention;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Validation;

namespace Abblix.SharedSignals.Receiver;

/// <summary>
/// The host-agnostic core of a push delivery endpoint (RFC 8935, carried by SSF 1.0
/// Section 6.1.1): one method from the raw transmission - content type and body - to the
/// <see cref="PushDeliveryResult"/> the transport renders. A host adapter owns routing and
/// transmitter authentication; this type owns everything the specifications say about the SET
/// itself.
/// </summary>
/// <remarks>
/// The order inside is the security order. Validation decides first; the replay cache is asked
/// only about a token that proved itself, so an attacker cannot burn identifiers with forgeries;
/// and the sink consumes only what both let through. A repeat is acknowledged without
/// re-processing - RFC 8935 Section 2 lets a transmitter redeliver regardless of earlier
/// responses, so a duplicate is the protocol working, not failing.
/// </remarks>
/// <param name="validator">The validation profile - typically the composed pipeline.</param>
/// <param name="options">What this receiver expects of every token on the stream.</param>
/// <param name="sink">Where validated events land.</param>
/// <param name="replayCache">
/// Tells first deliveries from repeats; null runs without replay tracking, leaving idempotency
/// entirely to the sink's contract.</param>
public sealed class PushDeliveryHandler(
    ISecurityEventTokenValidator validator,
    SsfValidationOptions options,
    ISecurityEventSink sink,
    IReplayCache? replayCache = null)
{
    /// <summary>
    /// Handles one push transmission.
    /// </summary>
    /// <param name="contentType">The request's Content-Type header, as received.</param>
    /// <param name="body">The request body: one SET in compact serialization.</param>
    /// <param name="cancellationToken">Cancels validation I/O and processing.</param>
    public async Task<PushDeliveryResult> HandleAsync(
        string? contentType,
        string? body,
        CancellationToken cancellationToken = default)
    {
        // "The SET Transmitter ... [uses] a media type of 'application/secevent+jwt'"
        // (RFC 8935 Section 2.1) - parsed as a media type, so parameters like charset do not
        // fail a conformant transmitter.
        if (!MediaTypeHeaderValue.TryParse(contentType, out var mediaType)
            || !string.Equals(
                mediaType.MediaType,
                SecurityEventTokenMediaTypes.SecurityEventToken,
                StringComparison.OrdinalIgnoreCase))
        {
            return PushDeliveryResult.BadRequest(new DeliveryError(
                DeliveryErrorCodes.InvalidRequest,
                $"The transmission arrived as '{contentType ?? "(no content type)"}', where RFC 8935 "
                + $"Section 2.1 requires '{SecurityEventTokenMediaTypes.SecurityEventToken}'."));
        }

        if (string.IsNullOrWhiteSpace(body))
        {
            return PushDeliveryResult.BadRequest(new DeliveryError(
                DeliveryErrorCodes.InvalidRequest,
                "The transmission carries no SET: the request body is the token itself "
                + "(RFC 8935 Section 2.1)."));
        }

        var verdict = await validator.ValidateAsync(body, options, cancellationToken);
        if (verdict.TryGetFailure(out var error))
        {
            return PushDeliveryResult.BadRequest(new DeliveryError(
                DeliveryErrorCodes.FromValidationError(error.Code),
                error.Description));
        }

        verdict.TryGetSuccess(out var validated);

        if (replayCache is not null)
        {
            // The default profile requires each of these envelope claims with its own step, so a
            // miss here means a weakened profile let an incomplete envelope through - and a token
            // replay accounting cannot track must not slip past it. The miss fails closed.
            if (validated!.Token is not { Issuer: { } issuer, JwtId: { } jwtId, IssuedAt: { } issuedAt })
            {
                return PushDeliveryResult.BadRequest(new DeliveryError(
                    DeliveryErrorCodes.InvalidRequest,
                    "The SET lacks an envelope claim replay accounting keys on: 'iss', 'jti' and "
                    + "'iat' are REQUIRED (RFC 8417 Section 2.2)."));
            }

            // The issuer belongs in the key because "jti" is unique only "within a particular
            // event feed" (RFC 8417 Section 2.2), and escaping removes ':' from both halves so
            // two distinct pairs cannot compose onto one identifier.
            var identifier =
                $"{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(jwtId)}";

            if (!await replayCache.TryReserveAsync(
                    identifier,
                    issuedAt + options.ReplayRetention,
                    cancellationToken))
            {
                // A redelivery of something already processed: acknowledged, never re-consumed.
                return PushDeliveryResult.Accepted;
            }
        }

        var refusal = await sink.ConsumeAsync(validated!, cancellationToken);
        return refusal is null
            ? PushDeliveryResult.Accepted
            : PushDeliveryResult.BadRequest(refusal);
    }
}
