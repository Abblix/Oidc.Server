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

using Abblix.SharedSignals.Model.Delivery;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Drains every push stream's queue on a timer.
/// </summary>
/// <remarks>
/// Push delivery is the transmitter reaching out, so something has to decide when. Without this a
/// host that wired the transmitter and mapped its endpoints got streams created, events minted,
/// signed and queued - and nothing delivered, with nothing logged and no error anywhere, because
/// every part worked and none of them was called. Poll streams worked throughout, which made it
/// read as "push is broken" rather than "push was never started".
/// <para>
/// A pass is best-effort by design. One stream's failure must not stop the others, so each is
/// caught and logged and the sweep continues; the sender itself decides what a failed delivery
/// means for the queue, keeping a transient refusal and dropping a final one.
/// </para>
/// <para>
/// Every instance of the application runs this, so each stream is claimed through an
/// <see cref="IDeliveryLease"/> before it is swept. Without that, a pass reads a queue the other
/// instances are reading at the same moment and every one of them POSTs the same SETs - which
/// RFC 8935 Section 2 tells a transmitter not to do outside a suspected recoverable failure. The
/// claim is what makes running N instances a division of the streams rather than N copies of the
/// work.
/// </para>
/// </remarks>
/// <param name="logger">Records what a pass did, and what it could not do.</param>
/// <param name="store">Where the streams to sweep are read from.</param>
/// <param name="sender">Performs one stream's pass.</param>
/// <param name="lease">Decides which instance sweeps a given stream this round.</param>
/// <param name="options">Carries the interval between passes and the claim's duration.</param>
/// <param name="timeProvider">The clock the timer and the deadlines run on; a test hands in a fake.</param>
public sealed partial class PushDeliveryScheduler(
    ILogger<PushDeliveryScheduler> logger,
    IStreamStore store,
    PushDeliverySender sender,
    IDeliveryLease lease,
    SharedSignalsTransmitterOptions options,
    TimeProvider timeProvider) : BackgroundService
{
    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (options.PushDeliveryInterval is not { } interval)
            return;

        // Named rather than described, because the name of the implementation is the fact an
        // operator needs: a sweep coordinated by ProcessLocalDeliveryLease is one instance's,
        // whatever the deployment believes it is running.
        LogSweepingStarted(interval, lease.GetType().Name);

        using var timer = new PeriodicTimer(interval, timeProvider);

        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            // A pass that throws must not take the host down with it. The exception filter keeps
            // shutdown silent: a cancelled pass is the host stopping, not a fault to report.
            try
            {
                await SweepAsync(stoppingToken);
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                LogSweepFailed(exception, interval);
            }
        }
    }

    /// <summary>
    /// Delivers what is pending on every enabled push stream this instance can claim.
    /// </summary>
    private async Task SweepAsync(CancellationToken cancellationToken)
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
