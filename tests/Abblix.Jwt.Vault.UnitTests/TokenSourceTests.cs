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

using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// Refresh-on-use, on a fake clock that only ever answers "what time is it" - there are no timers to
/// race. The case the design centres on is the max-TTL ceiling: renewal there does not fail, it
/// succeeds with a shrinking lease, so the source must log in afresh the moment the lease stops
/// extending, while the old token is still valid.
/// </summary>
public sealed class TokenSourceTests : IDisposable
{
    private readonly FakeTimeProvider _clock = new();
    private readonly List<HttpClient> _httpClients = [];

    private int _logins;
    private int _renewals;
    private string? _renewedTokenSeen;
    private Func<int, HttpResponseMessage> _onLogin;
    private Func<int, HttpResponseMessage> _onRenew;

    public TokenSourceTests()
    {
        _onLogin = attempt => Auth($"s.minted-{attempt}", 3600, renewable: true);
        _onRenew = _ => Auth("s.minted-1", 3600, renewable: true);
    }

    private static HttpResponseMessage Auth(string token, long leaseSeconds, bool renewable)
        => StubHttpMessageHandler.Json(HttpStatusCode.OK, new
        {
            auth = new { client_token = token, lease_duration = leaseSeconds, renewable },
        });

    private TokenSource SourceOver(VaultTransitOptions options)
    {
        var transport = new StubHttpMessageHandler((request, _) =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/login", StringComparison.Ordinal))
                return _onLogin(Interlocked.Increment(ref _logins));

            _renewedTokenSeen = request.Headers.TryGetValues(TokenHandler.TokenHeaderName, out var values)
                ? values.Single()
                : null;
            return _onRenew(Interlocked.Increment(ref _renewals));
        });
        var httpClient = new HttpClient(transport) { BaseAddress = new Uri("https://vault.test/v1/") };
        _httpClients.Add(httpClient);

        var monitor = new OptionsMonitorStub(options);
        return new TokenSource(
            NullLogger<TokenSource>.Instance,
            monitor,
            new LoginClient(NullLogger<LoginClient>.Instance, new StubHttpClientFactory(httpClient), monitor),
            _clock);
    }

    private static VaultTransitOptions WithAppRole(string? hostToken = null) => new()
    {
        Token = hostToken,
        Authentication = new VaultAuthenticationOptions
        {
            AppRole = new AppRoleAuthenticationOptions { RoleId = "r", SecretId = "s" },
        },
    };

    public void Dispose()
    {
        foreach (var httpClient in _httpClients)
            httpClient.Dispose();
    }

    [Fact]
    public async Task WithoutAuthentication_ServesTheHostToken_AndNeverLogsIn()
    {
        var source = SourceOver(new VaultTransitOptions { Token = "s.host" });

        Assert.Equal("s.host", await source.GetTokenAsync(TestContext.Current.CancellationToken));
        Assert.Equal(0, _logins);
    }

    [Fact]
    public async Task FirstUse_LogsIn_AndTheLiveTokenIsServedWithoutFurtherCalls()
    {
        var source = SourceOver(WithAppRole());

        var first = await source.GetTokenAsync(TestContext.Current.CancellationToken);
        _clock.Advance(TimeSpan.FromMinutes(10));
        var second = await source.GetTokenAsync(TestContext.Current.CancellationToken);

        Assert.Equal("s.minted-1", first);
        Assert.Equal("s.minted-1", second);
        Assert.Equal(1, _logins);
        Assert.Equal(0, _renewals);
    }

    /// <summary>
    /// Inside the grace window the caller is not made to pay for the refresh: the still-valid token is
    /// served at once, the renewal happens alongside, and the next caller sees its result. The renewal
    /// carries exactly the token being renewed.
    /// </summary>
    [Fact]
    public async Task InsideGrace_ServesTheOldTokenAtOnce_AndRenewsAlongside()
    {
        _onRenew = _ => Auth("s.minted-1", 3600, renewable: true);
        var source = SourceOver(WithAppRole());

        await source.GetTokenAsync(TestContext.Current.CancellationToken);

        // Grace is a jittered 10-20% of the lease, so 0.91 of it is inside the window whatever the roll.
        _clock.Advance(TimeSpan.FromSeconds(3600 * 0.91));
        var served = await source.GetTokenAsync(TestContext.Current.CancellationToken);
        Assert.Equal("s.minted-1", served);

        // The refresh ran alongside (the stub answers synchronously) and renewed, not re-logged-in.
        Assert.Equal(1, Volatile.Read(ref _renewals));
        Assert.Equal(1, Volatile.Read(ref _logins));
        Assert.Equal("s.minted-1", _renewedTokenSeen);
    }

    /// <summary>
    /// Before the refresh point nothing happens at all: no renewal, no login, no Vault traffic. This
    /// is what catches a regression to refreshing eagerly on every request.
    /// </summary>
    [Fact]
    public async Task BeforeGrace_MakesNoVaultCalls()
    {
        var source = SourceOver(WithAppRole());
        await source.GetTokenAsync(TestContext.Current.CancellationToken);

        // 0.65 of the lease is safely before the earliest possible refresh point (0.8 of it).
        _clock.Advance(TimeSpan.FromSeconds(3600 * 0.65));
        await source.GetTokenAsync(TestContext.Current.CancellationToken);

        Assert.Equal(1, _logins);
        Assert.Equal(0, _renewals);
    }

    [Fact]
    public async Task ExpiredToken_IsReplacedBeforeServing()
    {
        var source = SourceOver(WithAppRole());
        await source.GetTokenAsync(TestContext.Current.CancellationToken);

        _clock.Advance(TimeSpan.FromSeconds(3601));
        var served = await source.GetTokenAsync(TestContext.Current.CancellationToken);

        // The old token is dead, so the caller waited for the replacement login - not a renewal, which
        // has nothing left to renew.
        Assert.Equal("s.minted-2", served);
        Assert.Equal(2, _logins);
        Assert.Equal(0, _renewals);
    }

    /// <summary>
    /// The max-TTL ceiling: the renewal succeeds but returns less than a login grants, so the source
    /// logs in immediately - the renewal bought the time in which the login runs.
    /// </summary>
    [Fact]
    public async Task WhenTheLeaseStopsExtending_LogsInAtOnce()
    {
        _onRenew = _ => Auth("s.minted-1", 600, renewable: true);
        var source = SourceOver(WithAppRole());
        await source.GetTokenAsync(TestContext.Current.CancellationToken);

        _clock.Advance(TimeSpan.FromSeconds(3600 * 0.91));
        var served = await source.GetTokenAsync(TestContext.Current.CancellationToken);
        Assert.Equal("s.minted-1", served);

        // The refresh saw the shrunken lease and went straight to login; the next call serves the
        // fresh token.
        Assert.Equal(1, _renewals);
        Assert.Equal(2, _logins);
        Assert.Equal("s.minted-2", await source.GetTokenAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task DeniedRenewal_FallsBackToLogin()
    {
        _onRenew = _ => StubHttpMessageHandler.Json(
            HttpStatusCode.Forbidden, new { errors = new[] { "permission denied" } });
        var source = SourceOver(WithAppRole());
        await source.GetTokenAsync(TestContext.Current.CancellationToken);

        _clock.Advance(TimeSpan.FromSeconds(3600 * 0.91));
        await source.GetTokenAsync(TestContext.Current.CancellationToken);

        Assert.Equal(1, _renewals);
        Assert.Equal(2, _logins);
    }

    /// <summary>
    /// A batch token says so at login: renewal is never attempted, and the refresh goes straight to a
    /// fresh login.
    /// </summary>
    [Fact]
    public async Task NonRenewableToken_IsNeverRenewed_OnlyReplaced()
    {
        _onLogin = attempt => Auth($"s.batch-{attempt}", 300, renewable: false);
        var source = SourceOver(WithAppRole());
        await source.GetTokenAsync(TestContext.Current.CancellationToken);

        _clock.Advance(TimeSpan.FromSeconds(300 * 0.91));
        await source.GetTokenAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, _renewals);
        Assert.Equal(2, _logins);
    }

    /// <summary>
    /// A failed login opens a backoff window: inside it callers fail fast - null token, no Vault
    /// traffic - instead of hammering a Vault that is down; past it the next caller retries.
    /// </summary>
    [Fact]
    public async Task FailedLogin_OpensABackoffWindow_ThenTheNextCallerRetries()
    {
        _onLogin = attempt => attempt == 1
            ? StubHttpMessageHandler.Json(HttpStatusCode.ServiceUnavailable, new { errors = new[] { "sealed" } })
            : Auth("s.minted-2", 3600, renewable: true);
        var source = SourceOver(WithAppRole());

        Assert.Null(await source.GetTokenAsync(TestContext.Current.CancellationToken));
        Assert.Null(await source.GetTokenAsync(TestContext.Current.CancellationToken));
        Assert.Equal(1, _logins);

        // The first retry delay is 10s jittered into [5s, 15s]; 16 seconds clears it whatever the roll.
        _clock.Advance(TimeSpan.FromSeconds(16));
        Assert.Equal("s.minted-2", await source.GetTokenAsync(TestContext.Current.CancellationToken));
        Assert.Equal(2, _logins);
    }

    /// <summary>
    /// A token without an expiry is served forever and never refreshed - re-logging in on a schedule
    /// would only hammer Vault for a token that cannot get any fresher.
    /// </summary>
    [Fact]
    public async Task NonExpiringToken_IsServedForever_WithoutRefreshes()
    {
        _onLogin = attempt => Auth($"s.root-{attempt}", 0, renewable: false);
        var source = SourceOver(WithAppRole());
        await source.GetTokenAsync(TestContext.Current.CancellationToken);

        _clock.Advance(TimeSpan.FromDays(365));
        var served = await source.GetTokenAsync(TestContext.Current.CancellationToken);

        Assert.Equal("s.root-1", served);
        Assert.Equal(1, _logins);
        Assert.Equal(0, _renewals);
    }

    /// <summary>
    /// Two callers arriving with no token share one login: the second waits on the first's refresh
    /// task rather than starting a competing one.
    /// </summary>
    [Fact]
    public async Task ConcurrentFirstCallers_ShareOneLogin()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _onLogin = attempt =>
        {
            release.Task.Wait(TimeSpan.FromSeconds(10));
            return Auth($"s.minted-{attempt}", 3600, renewable: true);
        };
        var source = SourceOver(WithAppRole());

        // On the thread pool, because the refresh runs synchronously up to the (blocking) stub: started
        // inline it would block the test method itself before the release below could ever run.
        async Task<string?> GetAsync() => await source.GetTokenAsync(TestContext.Current.CancellationToken);
        var first = Task.Run(GetAsync);
        var second = Task.Run(GetAsync);
        release.SetResult();

        // Whatever the interleaving - both sharing the blocked refresh, or one finishing before the
        // other starts - one login serves both.
        Assert.Equal("s.minted-1", await first);
        Assert.Equal("s.minted-1", await second);
        Assert.Equal(1, _logins);
    }
}
