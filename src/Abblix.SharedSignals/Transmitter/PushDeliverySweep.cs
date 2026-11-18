// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Net.Http.Headers;
using Abblix.SharedSignals.Model.Delivery;
using Microsoft.Extensions.Logging;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Delivers the queue of every enabled push stream this instance can claim, one stream at a time.
/// </summary>
/// <remarks>
/// A pass is best-effort by design. One stream's failure must not stop the others, so each is caught and logged
/// and the pass continues; the sender itself decides what a failed delivery means for the queue, keeping a
/// transient refusal and dropping a final one.
/// <para>
/// A receiver that refuses with "Retry-After" is left alone until then (RFC 9110 Section 10.2.3, RFC 6585
/// Section 4), since sending sooner is what it asked not to receive. The wait is held in this instance only:
/// another instance that reaches the stream first meets the same answer and holds it too.
/// </para>
/// </remarks>
/// <param name="logger">Records what a pass could not do.</param>
/// <param name="store">Where the streams to sweep are read from.</param>
/// <param name="sender">Performs one stream's delivery.</param>
/// <param name="lease">Decides which instance sweeps a given stream this round.</param>
/// <param name="options">Carries the claim's duration.</param>
/// <param name="timeProvider">The clock the deadlines run on; a test hands in a fake.</param>
public sealed partial class PushDeliverySweep(
    ILogger<PushDeliverySweep> logger,
    IStreamStore store,
    PushDeliverySender sender,
    IDeliveryLease lease,
    SharedSignalsTransmitterOptions options,
    TimeProvider timeProvider) : IPushDeliverySweep
{
    /// <summary>The longest wait a receiver's "Retry-After" holds a stream for.</summary>
    /// <remarks>
    /// The receiver names the wait, and nothing in HTTP bounds it, so a receiver back after a minute that had
    /// answered with a week would otherwise go without its events for that week.
    /// </remarks>
    public static TimeSpan RetryAfterCeiling { get; } = TimeSpan.FromHours(1);

    private readonly ConcurrentDictionary<string, DateTimeOffset> _heldUntil = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public async Task SweepAsync(CancellationToken cancellationToken)
    {
        // A wait that has passed is dropped here rather than when its stream is next reached, so the wait of a
        // stream deleted meanwhile does not stay behind.
        var now = timeProvider.GetUtcNow();
        foreach (var (streamId, until) in _heldUntil)
        {
            if (until <= now)
                _heldUntil.TryRemove(streamId, out _);
        }

        foreach (var stream in await store.ListAllAsync(cancellationToken))
        {
            if (stream.Configuration.Delivery is not PushDeliveryMethod)
                continue;

            await SweepStreamAsync(stream, cancellationToken);
        }
    }

    /// <summary>
    /// Claims one stream and delivers its queue, or leaves it to whoever holds the claim.
    /// </summary>
    /// <remarks>
    /// The claim is per stream rather than per sweep, which is what turns several instances from
    /// duplicates into a division of labour: each takes the streams the others have not reached,
    /// and a stream whose receiver is slow holds up only itself.
    /// </remarks>
    private async Task SweepStreamAsync(StreamState stream, CancellationToken cancellationToken)
    {
        if (_heldUntil.ContainsKey(stream.StreamId))
        {
            LogStreamHeld(stream.StreamId);
            return;
        }

        var duration = options.PushDeliveryLeaseDuration;

        await using var claim = await lease.TryAcquireAsync(
            LeaseNameOf(stream.StreamId), duration, cancellationToken);

        if (claim is null)
        {
            LogStreamClaimedElsewhere(stream.StreamId);
            return;
        }

        // The claim runs out whether or not the pass has finished, and past that moment another
        // instance is entitled to this stream. So the pass is cut at the same deadline: one that
        // kept POSTing beyond it would be the duplicate delivery the claim exists to prevent,
        // and what it drops is redelivered on the next pass, which the queue is built for.
        using var deadline = new CancellationTokenSource(duration, timeProvider);
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);

        try
        {
            var outcome = await sender.SendPendingAsync(stream, bounded.Token);
            if (HoldOf(outcome.RetryAfter) is { } until)
            {
                _heldUntil[stream.StreamId] = until;
                LogStreamHeldUntil(stream.StreamId, until);
            }
        }
        catch (OperationCanceledException)
            when (deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            LogStreamPassCutOff(stream.StreamId, duration);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            // One receiver being unreachable says nothing about the next one's stream.
            LogStreamFailed(exception, stream.StreamId);
        }
    }

    /// <summary>
    /// The moment a receiver's "Retry-After" holds its stream until, bounded by <see cref="RetryAfterCeiling"/>, or
    /// null when it named no wait still to come.
    /// </summary>
    private DateTimeOffset? HoldOf(RetryConditionHeaderValue? retryAfter)
    {
        var now = timeProvider.GetUtcNow();
        DateTimeOffset? until = retryAfter switch
        {
            { Delta: { } delta } => now + delta,
            { Date: { } date } => date,
            null => null,
            _ => throw new InvalidOperationException(
                $"A {nameof(RetryConditionHeaderValue)} carries either a delay or a date."),
        };

        if (until is not { } moment || moment <= now)
            return null;

        var ceiling = now + RetryAfterCeiling;
        return moment < ceiling ? moment : ceiling;
    }

    /// <summary>
    /// Scopes the claim to this work, so a later claim over the same stream - a retention sweep,
    /// a verification - does not silently exclude delivery by sharing its name.
    /// </summary>
    private static string LeaseNameOf(string streamId) => $"push:{streamId}";
}
