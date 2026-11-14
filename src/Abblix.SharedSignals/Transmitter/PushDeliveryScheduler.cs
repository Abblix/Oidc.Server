// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
/// <param name="logger">Records that sweeping started, and a pass that failed.</param>
/// <param name="sweep">Runs one pass.</param>
/// <param name="lease">Named in the log, since it decides whether the sweep is shared between instances.</param>
/// <param name="options">Carries the interval between passes.</param>
/// <param name="timeProvider">The clock the timer runs on; a test hands in a fake.</param>
public sealed partial class PushDeliveryScheduler(
    ILogger<PushDeliveryScheduler> logger,
    IPushDeliverySweep sweep,
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
            // shutdown silent: a canceled pass is the host stopping, not a fault to report.
            try
            {
                await sweep.SweepAsync(stoppingToken);
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                LogSweepFailed(exception, interval);
            }
        }
    }
}
