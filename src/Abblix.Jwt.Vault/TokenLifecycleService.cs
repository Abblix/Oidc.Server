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

namespace Abblix.Jwt.Vault;

/// <summary>
/// Owns the Vault token for the process lifetime when the host configured
/// <see cref="VaultTransitOptions.Authentication"/>: logs in, renews the lease before it ends, and logs in
/// again - while the old token is still valid - once the lease stops extending. Idle when the section is
/// absent, which is the off switch.
/// </summary>
/// <remarks>
/// The renewal schedule is a port of the algorithm Vault Agent itself runs (its API client's lifetime
/// watcher), because the failure mode it prevents is not obvious: near the role's maximum TTL, renewals do
/// not fail - they succeed with a shrinking lease, and the first refusal arrives only after the token is
/// already dead. So the loop renews at two thirds of each returned lease, keeps a jittered grace of 10-20%
/// of the lease, and hands over to a fresh login as soon as the remaining time falls within grace or the
/// lease stops growing - never on a refusal it would have to be dead to receive. A renewal denied outright
/// switches to watching the clock, which is also how a non-renewable batch token is handled from the start.
/// <para>
/// Every replica logs in for itself: a token names one holder, so N replicas holding N tokens is the design,
/// and no claim coordination applies. The loop never throws - a faulted background service silently stops
/// the host - and all waiting goes through <see cref="TimeProvider"/> so tests can drive the clock.
/// </para>
/// </remarks>
internal sealed partial class TokenLifecycleService(
    ILogger<TokenLifecycleService> logger,
    LoginClient loginClient,
    TokenSource tokens,
    IOptionsMonitor<VaultTransitOptions> options,
    TimeProvider timeProvider) : BackgroundService
{
    /// <summary>First retry delay after a failed login or renewal, doubling up to <see cref="RetryCeiling"/>.
    /// The values Vault Agent's own watcher retries with.</summary>
    private static readonly TimeSpan RetryFloor = TimeSpan.FromSeconds(10);

    /// <summary>The longest delay between retries of a failing login or renewal.</summary>
    private static readonly TimeSpan RetryCeiling = TimeSpan.FromMinutes(5);

    /// <summary>How long startup waits for the first login before proceeding without it.</summary>
    private static readonly TimeSpan StartupWarmup = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Starts the loop and gives the first login a bounded head start, so a healthy host finishes starting
    /// with a token already in hand. A warm-up, not the correctness mechanism: whoever needs the token
    /// first awaits <see cref="TokenSource.FirstLoginCompleted"/> through the request pipeline, so a Vault
    /// that is down at startup delays requests, never correctness - and startup itself is not held hostage.
    /// </summary>
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await base.StartAsync(cancellationToken);

        if (options.CurrentValue.Authentication is not null)
            await Task.WhenAny(tokens.FirstLoginCompleted, Delay(StartupWarmup, cancellationToken));
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (options.CurrentValue.Authentication is null)
        {
            LogLifecycleDisabled();
            return;
        }

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var lease = await LoginUntilSuccessAsync(stoppingToken);
                    tokens.Publish(lease.Token);

                    if (lease.LeaseDuration <= TimeSpan.Zero)
                    {
                        // A lease of zero means the token never expires - a root or periodic-orphan posture.
                        // There is nothing to renew and re-logging in forever would only hammer Vault.
                        LogNonExpiringToken();
                        await Delay(Timeout.InfiniteTimeSpan, stoppingToken);
                        return;
                    }

                    await KeepAliveAsync(lease, stoppingToken);
                    LogReLogin();
                }
                catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
                {
                    // The backstop that makes "the loop never throws" true by construction: the login client
                    // translates the failures it can foresee into verdicts, and whatever it could not foresee
                    // must not take the host down - a faulted background service silently stops it. Log, back
                    // off, and go around; the token, if one is still valid, keeps working meanwhile.
                    LogUnexpectedFailure(exception);
                    await Delay(Jittered(RetryFloor), stoppingToken);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Host shutdown: the loop ends with the process, and the token idles out at its TTL.
        }
        finally
        {
            // A request waiting for the first login must not wait for a login nobody will perform.
            tokens.AbandonFirstLogin();
        }
    }

    private async Task<TokenLease> LoginUntilSuccessAsync(CancellationToken cancellationToken)
    {
        var retryDelay = RetryFloor;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var lease = await loginClient.LoginAsync(cancellationToken);
            if (lease is not null)
                return lease;

            await Delay(Jittered(retryDelay), cancellationToken);
            retryDelay = Min(retryDelay * 2, RetryCeiling);
        }
    }

    /// <summary>
    /// Renews the current token until its lease can no longer be usefully extended, then returns - with the
    /// token still valid - so the caller logs in afresh.
    /// </summary>
    private async Task KeepAliveAsync(TokenLease lease, CancellationToken cancellationToken)
    {
        // The anchor of the current lease: renewal measures time from the moment the lease was granted, and
        // only a successful renewal moves it.
        var anchor = timeProvider.GetUtcNow();
        var anchoredLease = lease.LeaseDuration;
        var prior = lease.LeaseDuration;
        var grace = Grace(prior);
        var nonRenewable = !lease.Renewable;
        TimeSpan? retryDelay = null;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            TimeSpan remaining;
            if (nonRenewable)
            {
                // Nothing to ask Vault: watch the clock until it is time to log in again.
                remaining = anchor + prior - timeProvider.GetUtcNow();
            }
            else
            {
                var result = await loginClient.RenewSelfAsync(cancellationToken);
                switch (result.Status)
                {
                    case RenewStatus.PermissionDenied:
                        // The token cannot renew itself - by policy or because it is a batch token. Stop
                        // asking and fall through to the clock-watching branch above.
                        nonRenewable = true;
                        continue;

                    case RenewStatus.Failed:
                        // A failure that may pass. The lease keeps running from its last anchor while the
                        // retries back off underneath it.
                        remaining = anchor + anchoredLease - timeProvider.GetUtcNow();
                        retryDelay = retryDelay is null ? RetryFloor : Min(retryDelay.Value * 2, RetryCeiling);
                        break;

                    case RenewStatus.Renewed:
                        retryDelay = null;
                        anchor = timeProvider.GetUtcNow();
                        anchoredLease = result.Lease!.LeaseDuration;
                        remaining = anchoredLease;
                        break;

                    default:
                        throw new InvalidOperationException($"Unhandled {nameof(RenewStatus)}: {result.Status}.");
                }
            }

            TimeSpan sleep;
            if (retryDelay is null)
            {
                // While the lease keeps extending to full length the grace tracks it; once Vault starts
                // returning a shrinking lease - the max-TTL ceiling - the grace freezes and decides the exit.
                if (remaining > prior)
                    grace = Grace(remaining);

                // Two thirds of the lease, plus a third of the (jittered) grace so replicas spread out.
                sleep = TimeSpan.FromTicks(remaining.Ticks * 2 / 3 + grace.Ticks / 3);
            }
            else
            {
                sleep = Jittered(retryDelay.Value);

                // The remaining lease is the whole retry budget: once the next delay would outlive the
                // token, retrying stops and a fresh login takes over.
                if (remaining <= sleep)
                    return;
            }

            prior = remaining;

            // Hand over to a fresh login while this token is still valid: either the remaining time is
            // already within grace, or sleeping would land it there with too little budget left to renew.
            if (remaining <= grace || remaining - sleep <= grace)
                return;

            await Delay(sleep, cancellationToken);
        }
    }

    /// <summary>
    /// The window before expiry reserved for handing over to a fresh login: 10-20% of the lease, jittered so
    /// replicas do not log in as one. The port of the watcher's grace calculation.
    /// </summary>
    private static TimeSpan Grace(TimeSpan leaseDuration)
    {
        if (leaseDuration <= TimeSpan.Zero)
            return TimeSpan.Zero;

        var jitterMax = leaseDuration.Ticks / 10;
        return TimeSpan.FromTicks(jitterMax + (long)(Random.Shared.NextDouble() * jitterMax));
    }

    /// <summary>A delay spread across 50-150% of its nominal value, so failing replicas retry out of step.</summary>
    private static TimeSpan Jittered(TimeSpan delay)
        => TimeSpan.FromTicks((long)(delay.Ticks * (0.5 + Random.Shared.NextDouble())));

    private static TimeSpan Min(TimeSpan left, TimeSpan right) => left <= right ? left : right;

    private Task Delay(TimeSpan delay, CancellationToken cancellationToken)
        => Task.Delay(delay, timeProvider, cancellationToken);
}
