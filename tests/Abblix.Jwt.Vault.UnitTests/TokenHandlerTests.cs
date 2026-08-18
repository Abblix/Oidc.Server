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
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// Covers the one thing that makes a short-lived Vault token usable: the header is read per request, so a token
/// renewed by AppRole or Kubernetes auth takes effect without restarting the process.
/// </summary>
public sealed class TokenHandlerTests : IDisposable
{
    private readonly List<HttpClient> _httpClients = [];

    /// <summary>A monitor whose value the test can change, standing in for a renewed token.</summary>
    private sealed class MutableMonitor(VaultTransitOptions options) : IOptionsMonitor<VaultTransitOptions>
    {
        public VaultTransitOptions CurrentValue { get; set; } = options;

        public VaultTransitOptions Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<VaultTransitOptions, string?> listener) => null;
    }

    private HttpClient ClientOver(MutableMonitor monitor, StubHttpMessageHandler transport)
    {
        var handler = new TokenHandler(new TokenSource(monitor)) { InnerHandler = transport };
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://vault.test/v1/") };
        _httpClients.Add(httpClient);
        return httpClient;
    }

    /// <summary>
    /// When the package logs in itself and no token exists yet, a request waits for the first login
    /// instead of leaving without a token - and proceeds with the minted token the moment it lands.
    /// </summary>
    [Fact]
    public async Task WaitsForTheFirstLogin_WhenAuthenticationIsConfigured()
    {
        var monitor = new MutableMonitor(new VaultTransitOptions
        {
            Authentication = new VaultAuthenticationOptions
            {
                Kubernetes = new KubernetesAuthenticationOptions { Role = "signer" },
            },
        });
        var tokens = new TokenSource(monitor);
        string? seen = null;
        var transport = new StubHttpMessageHandler((request, _) =>
        {
            seen = request.Headers.TryGetValues(TokenHandler.TokenHeaderName, out var values)
                ? values.Single()
                : null;
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new { ok = true });
        });
        var handler = new TokenHandler(tokens) { InnerHandler = transport };
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://vault.test/v1/") };
        _httpClients.Add(httpClient);

        var pending = httpClient.GetAsync("transit/keys/oidc-sign", TestContext.Current.CancellationToken);
        Assert.False(pending.IsCompleted);

        tokens.Publish("s.minted");
        await pending;

        Assert.Equal("s.minted", seen);
    }

    /// <summary>
    /// Configuring authentication REPLACES a host-supplied token: a stale value left in
    /// configuration - the dead agent-rendered token this feature exists to retire - is never
    /// presented. The request waits for the minted token instead of presenting the corpse.
    /// </summary>
    [Fact]
    public async Task ConfiguredAuthentication_ReplacesTheHostToken_RatherThanPresentingIt()
    {
        var monitor = new MutableMonitor(new VaultTransitOptions
        {
            Token = "s.stale",
            Authentication = new VaultAuthenticationOptions
            {
                Kubernetes = new KubernetesAuthenticationOptions { Role = "signer" },
            },
        });
        var tokens = new TokenSource(monitor);
        string? seen = null;
        var transport = new StubHttpMessageHandler((request, _) =>
        {
            seen = request.Headers.TryGetValues(TokenHandler.TokenHeaderName, out var values)
                ? values.Single()
                : null;
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new { ok = true });
        });
        var handler = new TokenHandler(tokens) { InnerHandler = transport };
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://vault.test/v1/") };
        _httpClients.Add(httpClient);

        var pending = httpClient.GetAsync("transit/keys/oidc-sign", TestContext.Current.CancellationToken);
        Assert.False(pending.IsCompleted);

        tokens.Publish("s.minted");
        await pending;

        Assert.Equal("s.minted", seen);
    }

    /// <summary>
    /// An environment variable defined but empty is "no token", not a token of length zero: without
    /// authentication configured the header is simply absent, exactly as with no Token at all.
    /// </summary>
    [Fact]
    public async Task WhitespaceToken_ReadsAsNoToken()
    {
        var monitor = new MutableMonitor(new VaultTransitOptions { Token = "  " });
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
    /// The login request itself is marked anonymous: it must neither wait for the token it is about
    /// to produce nor carry a stale one onto an endpoint that ignores it.
    /// </summary>
    [Fact]
    public async Task AnonymousRequest_NeitherWaitsNorCarriesAToken()
    {
        var monitor = new MutableMonitor(new VaultTransitOptions
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
        var handler = new TokenHandler(new TokenSource(monitor)) { InnerHandler = transport };
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://vault.test/v1/") };
        _httpClients.Add(httpClient);

        using var request = new HttpRequestMessage(HttpMethod.Post, "auth/approle/login");
        request.Options.Set(TokenHandler.AnonymousRequest, true);
        await httpClient.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.False(seen!.Headers.Contains(TokenHandler.TokenHeaderName));
    }

    public void Dispose()
    {
        foreach (var httpClient in _httpClients)
            httpClient.Dispose();
    }

    [Fact]
    public async Task PresentsTheCurrentToken_NotTheOneConfiguredAtStartup()
    {
        var monitor = new MutableMonitor(new VaultTransitOptions { Token = "s.first" });
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

        // A renewal: the old token expires and AppRole mints a new one into configuration.
        monitor.CurrentValue = new VaultTransitOptions { Token = "s.renewed" };
        await httpClient.GetAsync("transit/keys/oidc-sign", TestContext.Current.CancellationToken);

        // The second call carries the new token. Stamped on the client instead, it would still send s.first, and
        // every Transit call would 403 once that token expired, until the process restarted.
        Assert.Equal(["s.first", "s.renewed"], seen);
    }

    [Fact]
    public async Task SendsNoHeader_WhenNoTokenIsConfigured()
    {
        var monitor = new MutableMonitor(new VaultTransitOptions { Token = null });
        HttpRequestMessage? seen = null;
        var transport = new StubHttpMessageHandler((request, _) =>
        {
            seen = request;
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new { ok = true });
        });

        await ClientOver(monitor, transport).GetAsync("transit/keys/oidc-sign", TestContext.Current.CancellationToken);

        Assert.False(seen!.Headers.Contains(TokenHandler.TokenHeaderName));
    }
}
