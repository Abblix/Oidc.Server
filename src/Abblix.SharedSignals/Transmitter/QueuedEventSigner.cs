// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Keeps a security event unsigned while it waits in the outbox, and signs it each time it leaves, so every
/// delivery carries the time it was sent as its issue time.
/// </summary>
/// <remarks>
/// A receiver judges "iat" against its own clock, by default within five minutes. A token signed when it was queued
/// carried that moment to every attempt, so an event that waited longer - a receiver down for a while, or the queue
/// behind it - was refused as stale, and the refusal is one a transmitter drops the event for. The identifier and
/// every other claim stay as they were queued, so a receiver that saw an earlier attempt recognizes the event.
/// </remarks>
/// <param name="signer">Signs the event at the moment it is delivered.</param>
/// <param name="clock">Supplies the issue time each delivery carries. Defaults to the system clock.</param>
public sealed class QueuedEventSigner(ISecurityEventTokenSigner signer, TimeProvider? clock = null)
{
    private const string HeaderMember = "header";
    private const string ClaimsMember = "claims";

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    /// <summary>
    /// The form <paramref name="token"/> waits in the outbox in: its header and claims, unsigned.
    /// </summary>
    public static string ToQueued(SecurityEventToken token)
        => new JsonObject
        {
            [HeaderMember] = token.Token.Header.Json.DeepClone(),
            [ClaimsMember] = token.Token.Payload.Json.DeepClone(),
        }.ToJsonString();

    /// <summary>
    /// The SET to send for <paramref name="item"/>, signed now with the current time as its issue time.
    /// </summary>
    /// <remarks>
    /// An item queued by a version that signed on enqueue already holds a compact token. It is sent as it is, so
    /// events waiting when the transmitter is upgraded are still delivered.
    /// </remarks>
    /// <returns>The SET to send, or null when the item holds neither a token nor an unsigned form. An earlier
    /// version that rewrites a durable outbox whole drops the unsigned member it does not know, which leaves an item
    /// like that.</returns>
    public async Task<string?> SignAsync(OutboxItem item, CancellationToken cancellationToken = default)
        => item switch
        {
            { Unsigned: { } unsigned } => await SignUnsignedAsync(unsigned, cancellationToken),
            { CompactToken: { } compactToken } => compactToken,
            _ => null,
        };

    private async Task<string> SignUnsignedAsync(string unsigned, CancellationToken cancellationToken)
    {
        var queued = JsonNode.Parse(unsigned)!.AsObject();
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(queued[HeaderMember]!.AsObject()),
            Payload = new JsonWebTokenPayload(queued[ClaimsMember]!.AsObject()),
        };
        token.Payload.IssuedAt = _clock.GetUtcNow();

        return await signer.SignAsync(new SecurityEventToken(token), cancellationToken);
    }
}
