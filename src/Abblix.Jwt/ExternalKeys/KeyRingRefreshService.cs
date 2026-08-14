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


using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Brings the key ring up before the server serves anything, and keeps it current afterwards: it mints the key a
/// new period is due and picks up keys other pods minted.
/// </summary>
/// <remarks>
/// The first refresh runs in <c>StartAsync</c>, so a ring that cannot be read or opened stops the process rather
/// than letting it serve without keys. Later refreshes tick on the propagation window rather than the rotation
/// interval: a pod must notice a key another pod minted while that key is still announced, because once it goes
/// active every pod has to be able to verify it.
/// <para>
/// The two differ deliberately in what a failure means. At startup there is nothing to serve, so failing is the
/// honest answer. Afterwards the ring is already open in memory and signing needs no custodian at all, which is
/// the whole point of this placement - so a later failure costs only freshness, and taking the process down for
/// it would convert a custodian outage into an outage of everything the server does.
/// </para>
/// </remarks>
internal sealed partial class KeyRingRefreshService(
    ILogger<KeyRingRefreshService> logger,
    KeyRing ring,
    IOptions<KeyRingOptions> options,
    TimeProvider timeProvider) : BackgroundService
{
    /// <inheritdoc />
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await ring.RefreshAsync(cancellationToken);
        await base.StartAsync(cancellationToken);
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Half the propagation window: a freshly minted key is announced for that window before it signs, so
        // refreshing twice per window means no pod meets a token signed by a key it has not loaded.
        var period = options.Value.KeyRolloverPropagation / 2;
        using var timer = new PeriodicTimer(period, timeProvider);

        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await ring.RefreshAsync(stoppingToken);
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                // Every tick is a fresh attempt, so a failure costs one period of staleness and nothing more.
                // Letting it escape would end ExecuteAsync, and the host's default behaviour for a faulted
                // background service is to stop the process - so the pods would leave one after another over a
                // single rotation window while still holding perfectly good keys.
                LogRefreshFailed(exception, period);
            }
        }
    }
}
