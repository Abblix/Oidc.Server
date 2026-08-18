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

    [Fact]
    public async Task RenewsAtTwoThirdsOfTheLease_AndKeepsTheTokenCurrent()
    {
        var (service, tokens) = ServiceOver(WithAppRole());

        await service.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            // The sleep is 2/3 lease + grace/3 with grace in [10%, 20%): at most 0.734 of the lease.
            _clock.Advance(TimeSpan.FromSeconds(3600 * 0.74));
            await Eventually(() => Volatile.Read(ref _renewals) >= 1);

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
    /// again before that shrunken lease runs out - a refusal never comes while the token is alive.
    /// </summary>
    [Fact]
    public async Task WhenTheLeaseStopsExtending_LogsInAgainBeforeItExpires()
    {
        _onRenew = _ => Auth("s.minted", 600, renewable: true);
        var (service, _) = ServiceOver(WithAppRole());

        await service.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            _clock.Advance(TimeSpan.FromSeconds(3600 * 0.74));
            await Eventually(() => Volatile.Read(ref _renewals) >= 1);

            // The shrunken lease runs 600 virtual seconds. Walk the clock through it in grace-sized
            // steps: the re-login must arrive strictly inside the old token's remaining lifetime.
            for (var step = 0; step < 10 && Volatile.Read(ref _logins) < 2; step++)
            {
                _clock.Advance(TimeSpan.FromSeconds(59));
                await Task.Delay(20, TestContext.Current.CancellationToken);
            }

            await Eventually(() => Volatile.Read(ref _logins) >= 2);
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
            for (var step = 0; step < 80 && Volatile.Read(ref _logins) < 2; step++)
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
            for (var step = 0; step < 40 && Volatile.Read(ref _logins) < 2; step++)
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
