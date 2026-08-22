// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net.Http.Headers;
using Abblix.Jwt.ReplayPrevention;
using Abblix.SecurityEvents.Validation;

namespace Abblix.SecurityEvents.Delivery;

/// <summary>
/// The host-agnostic core of a push delivery endpoint (RFC 8935): one method from the raw
/// transmission - content type and body - to the <see cref="PushDeliveryResult"/> the transport
/// renders. A host adapter owns routing and transmitter authentication; this type owns everything
/// the specifications say about the SET itself.
/// </summary>
/// <remarks>
/// <para>
/// The order inside is the security order. Validation decides first; the replay cache is asked
/// only about a token that proved itself, so an attacker cannot burn identifiers with forgeries;
/// and the sink consumes only what both let through. A repeat is acknowledged without
/// re-processing - RFC 8935 Section 2 lets a transmitter redeliver regardless of earlier
/// responses, so a duplicate is the protocol working, not failing.
/// </para>
/// <para>
/// Nothing here knows which profile of SET it carries. RFC 8935 is a delivery specification and
/// the kinds it delivers are somebody else's business, so the three things that differ between
/// consumers - the validation profile, what that profile expects, and where events land - arrive
/// as parameters. The consumer's own registration binds them, which is also why the profile
/// cannot be named by a keyed-service attribute here: an attribute takes a compile-time constant,
/// and the key belongs to whoever registers this.
/// </para>
/// </remarks>
/// <param name="validator">
/// The validation pipeline, which the registering consumer resolves from its OWN named profile -
/// never the host's plain family, which another consumer of security event tokens may have shaped
/// to refuse every SET of this kind.</param>
/// <param name="options">What that consumer expects of every token it accepts.</param>
/// <param name="sink">Where validated events land.</param>
/// <param name="replayCache">
/// Tells first deliveries from repeats; null runs without replay tracking, leaving idempotency
/// entirely to the sink's contract.</param>
public sealed class PushDeliveryHandler(
    ISecurityEventTokenValidator validator,
    SecurityEventTokenValidationOptions options,
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

        var validated = verdict.GetSuccess();

        // The default profile requires each of these envelope claims with its own step, so a miss
        // here means a weakened profile let an incomplete envelope through - and a token replay
        // accounting cannot track must not slip past it. The miss fails closed.
        if (replayCache is not null
            && validated.Token is not { Issuer: not null, JwtId: not null, IssuedAt: not null })
        {
            return PushDeliveryResult.BadRequest(new DeliveryError(
                DeliveryErrorCodes.InvalidRequest,
                "The SET lacks an envelope claim replay accounting keys on: 'iss', 'jti' and "
                + "'iat' are REQUIRED (RFC 8417 Section 2.2)."));
        }

        var refusal = await sink.ConsumeAsync(validated!, cancellationToken);
        if (refusal is not null)
            return PushDeliveryResult.BadRequest(refusal);

        await RecordAsync(validated!, cancellationToken);
        return PushDeliveryResult.Accepted;
    }

    /// <summary>
    /// Records an accepted token, so a host reading the cache sees what this receiver consumed.
    /// </summary>
    /// <remarks>
    /// After the sink, never before it. A reservation made first stands whatever the sink then
    /// answers, so a delivery the sink refused would be remembered as handled - and the
    /// transmitter's retry, which RFC 8935 Section 2 both permits and expects, would be answered
    /// 202 without the sink ever seeing the event. That is the one path in this handler that loses
    /// a security event outright while reporting success.
    /// <para>
    /// The consequence is that a repeat reaches the sink again rather than being short-circuited
    /// here. That is what <see cref="ISecurityEventSink"/> already requires of it - "Processing
    /// must be idempotent" - and it is the only correct short-circuit available while
    /// <see cref="IReplayCache"/> can reserve but not release: a cache entry cannot be undone when
    /// the work it stands for failed, so it must not be written until that work has succeeded.
    /// </para>
    /// </remarks>
    private async Task RecordAsync(
        ValidatedSecurityEventToken validated, CancellationToken cancellationToken)
    {
        if (replayCache is null)
            return;

        var token = validated.Token;
        if (token is { Issuer: { } issuer, JwtId: { } jwtId, IssuedAt: { } issuedAt })
        {
            await replayCache.TryReserveAsync(
                ReplayIdentifier.ForToken(issuer, jwtId),
                issuedAt + options.ReplayRetention,
                cancellationToken);
        }
    }
}
