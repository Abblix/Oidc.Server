// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;
using Abblix.Jwt.ExternalKeys;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// The handler's own contract: the token is read fresh per request - which is what lets a token
/// renewed, replaced or rotated by the host take effect without a restart - and a self-authenticated
/// request passes through untouched.
/// </summary>
public sealed class TokenHandlerTests : IDisposable
{
    private readonly FakeTimeProvider _clock = new();
    private readonly List<HttpClient> _httpClients = [];

    private HttpClient ClientOver(OptionsMonitorStub monitor, StubHttpMessageHandler transport)
    {
        // The login client rides the same transport the assertions watch, exactly as in production.
        var factoryClient = new HttpClient(transport) { BaseAddress = new Uri("https://vault.test/v1/") };
        _httpClients.Add(factoryClient);
        var tokens = new TokenSource(
            NullLogger<TokenSource>.Instance,
            monitor,
            new LoginClient(NullLogger<LoginClient>.Instance, new StubHttpClientFactory(factoryClient), monitor),
            _clock);

        var handler = new TokenHandler(tokens) { InnerHandler = transport };
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://vault.test/v1/") };
        _httpClients.Add(httpClient);
        return httpClient;
    }


    [Fact]
    public async Task ALoginThatHasNotSucceededIsReportedAsTemporary()
    {
        // A deployment that logs in has no token only while a failed login waits out its backoff. Sending the
        // request anyway draws the vault's answer to a request with no credentials, and that answer says the
        // caller may not do this - a permanent reading of a condition that is ours and temporary.
        var monitor = new OptionsMonitorStub(new VaultTransitOptions
        {
            Authentication = new VaultAuthenticationOptions
            {
                AppRole = new AppRoleAuthenticationOptions { RoleId = "r", SecretId = "s" },
            },
        });

        var transport = new StubHttpMessageHandler((request, _) =>
            request.RequestUri!.AbsolutePath.EndsWith("/login", StringComparison.Ordinal)
                ? StubHttpMessageHandler.Json(
                    HttpStatusCode.Forbidden, new { errors = new[] { "permission denied" } })
                : StubHttpMessageHandler.Json(HttpStatusCode.OK, new { }));

        var client = ClientOver(monitor, transport);

        await Assert.ThrowsAsync<KeyCustodianUnavailableException>(
            () => client.GetAsync("transit/keys/oidc-sign", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task NoTokenAndNoLoginConfiguredIsNotAFailureAtAll()
    {
        // The control. A deployment that configures no authentication and no token talks to a vault that wants
        // neither, and turning that into an outage would refuse every such deployment at the first request.
        var monitor = new OptionsMonitorStub(new VaultTransitOptions());
        var transport = new StubHttpMessageHandler((_, _) =>
            StubHttpMessageHandler.Json(HttpStatusCode.OK, new { }));

        var client = ClientOver(monitor, transport);

        var response = await client.GetAsync(
            "transit/keys/oidc-sign", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    public void Dispose()
    {
        foreach (var httpClient in _httpClients)
            httpClient.Dispose();
    }

    [Fact]
    public async Task PresentsTheCurrentToken_NotTheOneConfiguredAtStartup()
    {
        var monitor = new OptionsMonitorStub(new VaultTransitOptions { Token = "s.first" });
        var seen = new List<string?>();
        var transport = new StubHttpMessageHandler((request, _) =>
        {
            seen.Add(request.Headers.TryGetValues(TokenHandler.TokenHeaderName, out var values)
                ? values.Single()
                : null);
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new { ok = true });
        });

        var httpClient = ClientOver(monitor, transport);
        await httpClient.GetAsync("transit/keys/oidc-sign", TestContext.Current.CancellationToken);

        // A rotation: the host delivers a new token through configuration reload.
        monitor.CurrentValue = new VaultTransitOptions { Token = "s.renewed" };
        await httpClient.GetAsync("transit/keys/oidc-sign", TestContext.Current.CancellationToken);

        // The second call carries the new token. Stamped on the client instead, it would still send s.first,
        // and every Transit call would 403 once that token expired, until the process restarted.
        Assert.Equal(["s.first", "s.renewed"], seen);
    }

    [Fact]
    public async Task SendsNoHeader_WhenNoTokenIsConfigured()
    {
        var monitor = new OptionsMonitorStub(new VaultTransitOptions { Token = null });
        HttpRequestMessage? seen = null;
        var transport = new StubHttpMessageHandler((request, _) =>
        {
            seen = request;
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new { ok = true });
        });

        await ClientOver(monitor, transport).GetAsync("transit/keys/oidc-sign", TestContext.Current.CancellationToken);

        Assert.False(seen!.Headers.Contains(TokenHandler.TokenHeaderName));
    }

    /// <summary>
    /// An environment variable defined but empty is "no token", not a token of length zero: without
    /// authentication configured the header is simply absent, exactly as with no Token at all.
    /// </summary>
    [Fact]
    public async Task WhitespaceToken_ReadsAsNoToken()
    {
        var monitor = new OptionsMonitorStub(new VaultTransitOptions { Token = "  " });
        HttpRequestMessage? seen = null;
        var transport = new StubHttpMessageHandler((request, _) =>
        {
            seen = request;
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new { ok = true });
        });

        await ClientOver(monitor, transport).GetAsync("transit/keys/oidc-sign", TestContext.Current.CancellationToken);

        Assert.False(seen!.Headers.Contains(TokenHandler.TokenHeaderName));
    }

    /// <summary>
    /// With authentication configured, the first request drives the login itself - refresh-on-use has
    /// no background actor - and proceeds with the minted token, never with whatever stale Token the
    /// configuration still carries: configuring authentication replaces it.
    /// </summary>
    [Fact]
    public async Task ConfiguredAuthentication_LogsInOnFirstUse_AndReplacesTheHostToken()
    {
        var monitor = new OptionsMonitorStub(new VaultTransitOptions
        {
            Token = "s.stale",
            Authentication = new VaultAuthenticationOptions
            {
                AppRole = new AppRoleAuthenticationOptions { RoleId = "r", SecretId = "s" },
            },
        });
        var seen = new List<string?>();
        var transport = new StubHttpMessageHandler((request, _) =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/login", StringComparison.Ordinal))
                return StubHttpMessageHandler.Json(HttpStatusCode.OK, new
                {
                    auth = new { client_token = "s.minted", lease_duration = 3600, renewable = true },
                });

            seen.Add(request.Headers.TryGetValues(TokenHandler.TokenHeaderName, out var values)
                ? values.Single()
                : null);
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new { ok = true });
        });

        await ClientOver(monitor, transport).GetAsync("transit/keys/oidc-sign", TestContext.Current.CancellationToken);

        Assert.Equal(["s.minted"], seen);
    }

    /// <summary>
    /// A self-authenticated request - the source's own login or renewal - passes through untouched:
    /// no token attached, and no ask back into the source, which would recurse into the refresh that
    /// sent it.
    /// </summary>
    [Fact]
    public async Task SelfAuthenticatedRequest_PassesThroughUntouched()
    {
        var monitor = new OptionsMonitorStub(new VaultTransitOptions
        {
            Token = "s.host",
            Authentication = new VaultAuthenticationOptions
            {
                AppRole = new AppRoleAuthenticationOptions { RoleId = "r", SecretId = "s" },
            },
        });
        HttpRequestMessage? seen = null;
        var transport = new StubHttpMessageHandler((request, _) =>
        {
            seen = request;
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new { ok = true });
        });

        using var request = new HttpRequestMessage(HttpMethod.Post, "auth/approle/login");
        request.Options.Set(TokenHandler.SelfAuthenticated, true);
        await ClientOver(monitor, transport).SendAsync(request, TestContext.Current.CancellationToken);

        Assert.False(seen!.Headers.Contains(TokenHandler.TokenHeaderName));
    }
}
