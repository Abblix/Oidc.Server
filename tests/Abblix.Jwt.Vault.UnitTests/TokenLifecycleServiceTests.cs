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

using System.Diagnostics;
using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// The renewal schedule, driven on a fake clock. The case the whole design exists for: near the
/// role's maximum TTL Vault does not refuse renewals - it answers them successfully with a
/// shrinking lease - so the loop must hand over to a fresh login while the old token still works,
/// never wait for a refusal it would have to be dead to receive.
/// </summary>
public sealed class TokenLifecycleServiceTests : IDisposable
{
    private readonly FakeTimeProvider _clock = new();
    private readonly List<IDisposable> _disposables = [];

    private int _logins;
    private int _renewals;
    private Func<int, HttpResponseMessage> _onLogin = _ => Auth("s.minted", 3600, renewable: true);
    private Func<int, HttpResponseMessage> _onRenew = _ => Auth("s.minted", 3600, renewable: true);

    private static HttpResponseMessage Auth(string token, long leaseSeconds, bool renewable)
        => StubHttpMessageHandler.Json(HttpStatusCode.OK, new
        {
            auth = new { client_token = token, lease_duration = leaseSeconds, renewable },
        });

    private (TokenLifecycleService Service, TokenSource Tokens) ServiceOver(VaultTransitOptions options)
    {
        var transport = new StubHttpMessageHandler((request, _) =>
            request.RequestUri!.AbsolutePath.EndsWith("/login", StringComparison.Ordinal)
                ? _onLogin(Interlocked.Increment(ref _logins))
                : _onRenew(Interlocked.Increment(ref _renewals)));
        var httpClient = new HttpClient(transport) { BaseAddress = new Uri("https://vault.test/v1/") };
        _disposables.Add(httpClient);

        var monitor = new OptionsMonitorStub(options);
        var tokens = new TokenSource(monitor);
        var loginClient = new LoginClient(
            NullLogger<LoginClient>.Instance, new StubHttpClientFactory(httpClient), monitor);
        var service = new TokenLifecycleService(
            NullLogger<TokenLifecycleService>.Instance, loginClient, tokens, monitor, _clock);
        _disposables.Add(service);
        return (service, tokens);
    }

    private static VaultTransitOptions WithAppRole() => new()
    {
        Authentication = new VaultAuthenticationOptions
        {
            AppRole = new AppRoleAuthenticationOptions { RoleId = "r", SecretId = "s" },
        },
    };

    /// <summary>
    /// Waits on the real clock for the loop, running on the thread pool, to catch up with the fake
    /// one - the fake provider completes timers synchronously, but continuations still need to run.
    /// </summary>
    private static async Task Eventually(Func<bool> condition)
    {
        var stopwatch = Stopwatch.StartNew();
        while (!condition())
        {
            Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(10), "the condition was not reached in time");
            await Task.Delay(10, TestContext.Current.CancellationToken);
        }
    }

    public void Dispose()
    {
        foreach (var disposable in _disposables)
            disposable.Dispose();
    }

    [Fact]
    public async Task WithoutAuthentication_StaysIdle()
    {
        var (service, tokens) = ServiceOver(new VaultTransitOptions { Token = "s.host" });

        await service.StartAsync(TestContext.Current.CancellationToken);
        await service.StopAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, _logins);
        Assert.Equal("s.host", tokens.Current);
    }

    [Fact]
    public async Task StartAsync_ComesBackWithTheFirstTokenPublished()
    {
        var (service, tokens) = ServiceOver(WithAppRole());

        await service.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            Assert.True(tokens.FirstLoginCompleted.IsCompletedSuccessfully);
            Assert.Equal("s.minted", tokens.Current);
        }
        finally
        {
            await service.StopAsync(TestContext.Current.CancellationToken);
        }
    }

    /// <summary>
    /// The schedule itself: one renewal immediately on login (the watcher's own first move), none
    /// before two thirds of the lease, the next by 0.74 of it - the sleep is 2/3 lease + grace/3
    /// with grace in [10%, 20%), so it lands in [0.700, 0.734] of the lease. The lower bound is what
    /// catches a regression to renewing in a hot loop; the upper is what catches renewing too late.
    /// </summary>
    [Fact]
    public async Task RenewsOnLogin_ThenNotBeforeTwoThirds_ThenByThreeQuarters()
    {
        var (service, tokens) = ServiceOver(WithAppRole());

        await service.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            await Eventually(() => Volatile.Read(ref _renewals) == 1);

            _clock.Advance(TimeSpan.FromSeconds(3600 * 0.65));
            await Task.Delay(50, TestContext.Current.CancellationToken);
            Assert.Equal(1, Volatile.Read(ref _renewals));

            _clock.Advance(TimeSpan.FromSeconds(3600 * 0.09));
            await Eventually(() => Volatile.Read(ref _renewals) == 2);

            Assert.Equal(1, _logins);
            Assert.Equal("s.minted", tokens.Current);
        }
        finally
        {
            await service.StopAsync(TestContext.Current.CancellationToken);
        }
    }

    /// <summary>
    /// The max-TTL boundary: renewal succeeds but the returned lease shrinks. The loop must log in
    /// again strictly inside the shrunken lease - a refusal never comes while the token is alive.
    /// The responder shrinks only the first login's token; the fresh token renews to full length,
    /// the way a real re-login resets the max-TTL clock.
    /// </summary>
    [Fact]
    public async Task WhenTheLeaseStopsExtending_LogsInAgainBeforeItExpires()
    {
        var shrunkenLeaseStart = DateTimeOffset.MinValue;
        var secondLoginAt = DateTimeOffset.MinValue;
        _onLogin = attempt =>
        {
            if (attempt == 2)
                secondLoginAt = _clock.GetUtcNow();
            return Auth($"s.minted-{attempt}", 3600, renewable: true);
        };
        _onRenew = _ =>
        {
            if (Volatile.Read(ref _logins) != 1)
                return Auth("s.minted-2", 3600, renewable: true);

            shrunkenLeaseStart = _clock.GetUtcNow();
            return Auth("s.minted-1", 600, renewable: true);
        };
        var (service, _) = ServiceOver(WithAppRole());

        await service.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            await Eventually(() => Volatile.Read(ref _renewals) >= 1);

            // Walk the clock in steps that together stay under the 600-second shrunken lease: a
            // loop that re-logs in only after expiry cannot pass, because the budget never gets there.
            for (var step = 0; step < 9 && Volatile.Read(ref _logins) < 2; step++)
            {
                _clock.Advance(TimeSpan.FromSeconds(59));
                await Task.Delay(20, TestContext.Current.CancellationToken);
            }

            await Eventually(() => Volatile.Read(ref _logins) >= 2);
            Assert.True(
                secondLoginAt - shrunkenLeaseStart < TimeSpan.FromSeconds(600),
                $"the re-login came {secondLoginAt - shrunkenLeaseStart} after the lease shrank to 600s");
        }
        finally
        {
            await service.StopAsync(TestContext.Current.CancellationToken);
        }
    }

    /// <summary>
    /// A renewal denied outright means the token cannot renew itself at all: the loop stops asking
    /// and still logs in again before the original lease runs out.
    /// </summary>
    [Fact]
    public async Task WhenRenewalIsDenied_SwitchesToClockWatching_AndLogsInBeforeExpiry()
    {
        _onRenew = _ => StubHttpMessageHandler.Json(
            HttpStatusCode.Forbidden, new { errors = new[] { "permission denied" } });
        // Snapshot at the moment of the second login: the fresh cycle legitimately renews again
        // right after it, so the counter alone cannot prove the old cycle stopped asking.
        var renewalsAtSecondLogin = -1;
        _onLogin = attempt =>
        {
            if (attempt == 2)
                renewalsAtSecondLogin = Volatile.Read(ref _renewals);
            return Auth("s.minted", 3600, renewable: true);
        };
        var (service, _) = ServiceOver(WithAppRole());

        await service.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            // 70 x 50 = 3500 virtual seconds, strictly inside the 3600-second lease: a loop that
            // waits for the token to die before logging in again cannot pass on this budget.
            for (var step = 0; step < 70 && Volatile.Read(ref _logins) < 2; step++)
            {
                _clock.Advance(TimeSpan.FromSeconds(50));
                await Task.Delay(20, TestContext.Current.CancellationToken);
            }

            await Eventually(() => Volatile.Read(ref _logins) >= 2);
            Assert.Equal(1, renewalsAtSecondLogin);
        }
        finally
        {
            await service.StopAsync(TestContext.Current.CancellationToken);
        }
    }

    /// <summary>
    /// A batch token says so at login: no renewal is ever attempted, and the fresh login still
    /// arrives before the lease ends.
    /// </summary>
    [Fact]
    public async Task NonRenewableToken_IsNeverRenewed_OnlyReplacedInTime()
    {
        _onLogin = _ => Auth("s.batch", 300, renewable: false);
        var (service, _) = ServiceOver(WithAppRole());

        await service.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            // 29 x 10 = 290 virtual seconds, strictly inside the 300-second lease: the replacement
            // login must arrive while the batch token still lives.
            for (var step = 0; step < 29 && Volatile.Read(ref _logins) < 2; step++)
            {
                _clock.Advance(TimeSpan.FromSeconds(10));
                await Task.Delay(20, TestContext.Current.CancellationToken);
            }

            await Eventually(() => Volatile.Read(ref _logins) >= 2);
            Assert.Equal(0, _renewals);
        }
        finally
        {
            await service.StopAsync(TestContext.Current.CancellationToken);
        }
    }

    /// <summary>
    /// When the lifecycle stops before ever logging in - host shutdown during a Vault outage - a
    /// request waiting for the first login fails now, with the cause named, instead of burning its
    /// whole client timeout against a login nobody is performing.
    /// </summary>
    [Fact]
    public async Task StoppingBeforeTheFirstLogin_FailsTheWaitersRatherThanHangingThem()
    {
        _onLogin = _ => StubHttpMessageHandler.Json(
            HttpStatusCode.ServiceUnavailable, new { errors = new[] { "sealed" } });
        var (service, tokens) = ServiceOver(WithAppRole());

        var starting = service.StartAsync(TestContext.Current.CancellationToken);
        await Eventually(() => Volatile.Read(ref _logins) >= 1);
        _clock.Advance(TimeSpan.FromSeconds(6));
        await starting;

        await service.StopAsync(TestContext.Current.CancellationToken);

        await Eventually(() => tokens.FirstLoginCompleted.IsFaulted);
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => tokens.FirstLoginCompleted);
        Assert.Contains(nameof(TokenLifecycleService), exception.Message);
    }

    [Fact]
    public async Task FailedLogin_IsRetriedWithBackoff_UntilItSucceeds()
    {
        _onLogin = attempt => attempt == 1
            ? StubHttpMessageHandler.Json(HttpStatusCode.ServiceUnavailable, new { errors = new[] { "sealed" } })
            : Auth("s.second", 3600, renewable: true);
        var (service, tokens) = ServiceOver(WithAppRole());

        // The warm-up wait inside StartAsync must not block startup while Vault is down.
        var starting = service.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            await Eventually(() => starting.IsCompleted || Volatile.Read(ref _logins) >= 1);
            _clock.Advance(TimeSpan.FromSeconds(20));
            await starting;

            // The retry delay is 10s jittered into [5s, 15s]; 20 virtual seconds cover it.
            _clock.Advance(TimeSpan.FromSeconds(20));
            await Eventually(() => tokens.FirstLoginCompleted.IsCompletedSuccessfully);

            Assert.Equal("s.second", tokens.Current);
            Assert.Equal(2, _logins);
        }
        finally
        {
            await service.StopAsync(TestContext.Current.CancellationToken);
        }
    }
}
