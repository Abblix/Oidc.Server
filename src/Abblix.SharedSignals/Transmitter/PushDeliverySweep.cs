// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// <inheritdoc />
    public async Task SweepAsync(CancellationToken cancellationToken)
    {
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
            await sender.SendPendingAsync(stream, bounded.Token);
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
    /// Scopes the claim to this work, so a later claim over the same stream - a retention sweep,
    /// a verification - does not silently exclude delivery by sharing its name.
    /// </summary>
    private static string LeaseNameOf(string streamId) => $"push:{streamId}";
}
