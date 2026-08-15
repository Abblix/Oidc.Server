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
/// </remarks>
/// <param name="logger">Records what a pass did, and what it could not do.</param>
/// <param name="store">Where the streams to sweep are read from.</param>
/// <param name="sender">Performs one stream's pass.</param>
/// <param name="options">Carries the interval between passes.</param>
/// <param name="timeProvider">The clock the timer runs on; a test hands in a fake.</param>
public sealed partial class PushDeliveryScheduler(
    ILogger<PushDeliveryScheduler> logger,
    IStreamStore store,
    PushDeliverySender sender,
    SsfTransmitterOptions options,
    TimeProvider timeProvider) : BackgroundService
{
    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (options.PushDeliveryInterval is not { } interval)
            return;

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
    /// Delivers what is pending on every enabled push stream.
    /// </summary>
    private async Task SweepAsync(CancellationToken cancellationToken)
    {
        foreach (var stream in await store.ListAllAsync(cancellationToken))
        {
            if (stream.Configuration.Delivery is not PushDeliveryMethod)
                continue;

            try
            {
                await sender.SendPendingAsync(stream, cancellationToken);
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                // One receiver being unreachable says nothing about the next one's stream.
                LogStreamFailed(exception, stream.StreamId);
            }
        }
    }
}
