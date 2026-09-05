// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Jwt.Vault;

/// <summary>
/// The one place the Vault token lives, refreshed on use rather than by a background schedule: every
/// consumer of this package reaches Vault through <see cref="TokenHandler"/>, so the request that needs
/// the token is the natural moment to ask whether it is still fresh. A sidecar like Vault Agent must
/// renew proactively because its consumers do not pass through it; an in-process source has no such
/// constraint, and dropping the schedule drops with it a background service whose faults would stop the
/// host, its startup ordering, and its shutdown choreography.
/// </summary>
/// <remarks>
/// The schedule collapses into two clock reads. A token past its refresh point - a jittered 10-20% of
/// the lease before expiry - is still served, and a refresh starts alongside without delaying anyone;
/// the refresh task is kept, never orphaned: it cannot fault (every outcome is a verdict), and its
/// result is what the next caller reads. Only a caller with no live token at all waits, under its own
/// cancellation, while the refresh runs under the source's lifetime so one caller giving up cannot kill
/// the refresh every other caller is waiting for. A refresh failure opens a jittered exponential
/// backoff window (the retry pacing Vault Agent uses) inside which callers fail fast instead of
/// hammering a Vault that is down.
/// <para>
/// Renewal keeps the failure mode of the max-TTL ceiling in view: there Vault does not refuse -
/// renew-self succeeds with a shrinking lease, and the first refusal would arrive only after the token
/// died. So a renewal that returns less than the lease a fresh login granted means the ceiling is
/// close, and the source logs in again immediately - the old token is still valid for that call.
/// A denied renewal falls back to login the same way, which also covers batch tokens.
/// </para>
/// </remarks>
internal sealed partial class TokenSource(
    ILogger<TokenSource> logger,
    IOptionsMonitor<VaultTransitOptions> options,
    LoginClient loginClient,
    TimeProvider timeProvider)
{
    /// <summary>First retry delay after a failed refresh, doubling up to <see cref="RetryCeiling"/>.</summary>
    private static readonly TimeSpan RetryFloor = TimeSpan.FromSeconds(10);

    /// <summary>The longest backoff window a failing refresh can open.</summary>
    private static readonly TimeSpan RetryCeiling = TimeSpan.FromMinutes(5);

    /// <summary>Everything known about the token currently held. Immutable, so readers need no lock.</summary>
    /// <param name="Token">The token to present.</param>
    /// <param name="Renewable">Whether renew-self can extend it; a batch token cannot.</param>
    /// <param name="ExpiresAt">When the lease ends; <see cref="DateTimeOffset.MaxValue"/> for a token
    /// without an expiry.</param>
    /// <param name="RefreshAt">When to start refreshing: expiry minus the jittered grace.</param>
    /// <param name="FullLease">The lease a fresh login granted. A renewal returning less than this is
    /// the max-TTL ceiling announcing itself, and the answer is a new login.</param>
    private sealed record LeaseState(
        string Token,
        bool Renewable,
        DateTimeOffset ExpiresAt,
        DateTimeOffset RefreshAt,
        TimeSpan FullLease);

    // Entered through EnterScope rather than with a lock statement: the statement form on this type is a
    // C# 13 feature, and net8.0 compiles as C# 12 against the polyfill in Abblix.Utils.
    private readonly Lock _gate = new();
    private LeaseState? _state;
    private Task? _refresh;
    private DateTimeOffset _nextAttemptAt = DateTimeOffset.MinValue;
    private TimeSpan _retryDelay = TimeSpan.Zero;

    /// <summary>Whether the package logs in itself. Absent authentication means the host-supplied token.</summary>
    public bool AuthenticationConfigured => options.CurrentValue.Authentication is not null;

    /// <summary>
    /// The token to present right now, or null when there is none to present. With authentication
    /// configured this REPLACES a host-supplied token outright: a stale value left in configuration -
    /// the dead agent-rendered token this feature exists to retire - is never presented. Without it,
    /// the host-supplied token is read through the monitor so a rotation delivered by configuration
    /// reload takes effect per request; whitespace normalizes to null, so an env var defined but empty
    /// reads as "no token" everywhere.
    /// </summary>
    public async ValueTask<string?> GetTokenAsync(CancellationToken cancellationToken)
    {
        if (!AuthenticationConfigured)
        {
            var hostToken = options.CurrentValue.Token;
            return string.IsNullOrWhiteSpace(hostToken) ? null : hostToken;
        }

        var state = _state;
        if (state is not null && timeProvider.GetUtcNow() < state.ExpiresAt)
        {
            // The token is alive: serve it now, and if its refresh point has passed, start the refresh
            // alongside rather than making this caller pay for it. Discarded, not orphaned: the task is
            // kept in the field, cannot fault, and its result is what the next caller reads.
            if (timeProvider.GetUtcNow() >= state.RefreshAt)
                _ = StartRefresh();
            return state.Token;
        }

        // No live token: the refresh is this caller's only hope, so it waits - unless a recent failure
        // opened a backoff window, in which case the completed task falls straight through and the
        // caller fails fast rather than hammering a Vault that is down.
        await StartRefresh().WaitAsync(cancellationToken);

        return _state is { } fresh && timeProvider.GetUtcNow() < fresh.ExpiresAt ? fresh.Token : null;
    }

    /// <summary>
    /// Starts a refresh unless one is already in flight or a backoff window is open, and returns the
    /// task to await - already completed when nothing is running and nothing may start yet.
    /// </summary>
    private Task StartRefresh()
    {
        using (_gate.EnterScope())
        {
            if (_refresh is { IsCompleted: false } inFlight)
                return inFlight;

            if (timeProvider.GetUtcNow() < _nextAttemptAt)
                return Task.CompletedTask;

            return _refresh = RefreshAsync(_state);
        }
    }

    /// <summary>
    /// Renews or replaces the token. Never throws: every outcome lands in the state or in the backoff,
    /// because callers observe this task's completion, not its exception.
    /// </summary>
    private async Task RefreshAsync(LeaseState? prior)
    {
        try
        {
            if (prior is { Renewable: true } alive && timeProvider.GetUtcNow() < alive.ExpiresAt)
            {
                var renewal = await loginClient.RenewSelfAsync(alive.Token, CancellationToken.None);
                switch (renewal.Status)
                {
                    case RenewStatus.Renewed when renewal.Lease!.LeaseDuration >= alive.FullLease:
                        Publish(renewal.Lease);
                        return;

                    case RenewStatus.Renewed:
                        // The max-TTL ceiling: the lease stopped extending to full length. The renewal
                        // still bought time, so the login below happens while the token is valid.
                        LogLeaseStoppedExtending(renewal.Lease!.LeaseDuration, alive.FullLease);
                        break;

                    case RenewStatus.PermissionDenied:
                        // The token cannot renew itself - by policy or because it is already gone.
                        // Either way the answer is a fresh login, not another question.
                        break;

                    case RenewStatus.Failed:
                        RegisterFailure();
                        return;

                    default:
                        throw new InvalidOperationException($"Unhandled {nameof(RenewStatus)}: {renewal.Status}.");
                }
            }

            var lease = await loginClient.LoginAsync(CancellationToken.None);
            if (lease is null)
            {
                RegisterFailure();
                return;
            }

            Publish(lease);
        }
        catch (Exception exception)
        {
            // The backstop that keeps the never-throws promise: the login client translates the
            // failures it can foresee into verdicts, and whatever it could not foresee becomes a
            // backoff window instead of an unobserved task exception.
            LogUnexpectedFailure(exception);
            RegisterFailure();
        }
    }

    private void Publish(TokenLease lease)
    {
        LeaseState state;
        if (lease.LeaseDuration <= TimeSpan.Zero)
        {
            // A lease of zero means the token never expires - a root or periodic-orphan posture.
            // Nothing to refresh, ever.
            LogNonExpiringToken();
            state = new LeaseState(
                lease.Token, lease.Renewable, DateTimeOffset.MaxValue, DateTimeOffset.MaxValue, TimeSpan.Zero);
        }
        else
        {
            var now = timeProvider.GetUtcNow();
            var expiresAt = now + lease.LeaseDuration;
            state = new LeaseState(
                lease.Token, lease.Renewable, expiresAt, expiresAt - Grace(lease.LeaseDuration), lease.LeaseDuration);
        }

        using (_gate.EnterScope())
        {
            _state = state;
            _retryDelay = TimeSpan.Zero;
            _nextAttemptAt = DateTimeOffset.MinValue;
        }
    }

    private void RegisterFailure()
    {
        using (_gate.EnterScope())
        {
            _retryDelay = _retryDelay == TimeSpan.Zero ? RetryFloor : Min(_retryDelay * 2, RetryCeiling);
            _nextAttemptAt = timeProvider.GetUtcNow() + Jittered(_retryDelay);
        }
    }

    /// <summary>
    /// The window before expiry in which refreshing starts: 10-20% of the lease, jittered so replicas
    /// do not refresh as one. The grace calculation Vault Agent's own watcher uses.
    /// </summary>
    private static TimeSpan Grace(TimeSpan leaseDuration)
    {
        var jitterMax = leaseDuration.Ticks / 10;
        return TimeSpan.FromTicks(jitterMax + (long)(Random.Shared.NextDouble() * jitterMax));
    }

    /// <summary>A delay spread across 50-150% of its nominal value, so failing replicas retry out of step.</summary>
    private static TimeSpan Jittered(TimeSpan delay)
        => TimeSpan.FromTicks((long)(delay.Ticks * (0.5 + Random.Shared.NextDouble())));

    private static TimeSpan Min(TimeSpan left, TimeSpan right) => left <= right ? left : right;
}
