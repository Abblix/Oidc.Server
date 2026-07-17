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

namespace Abblix.Oidc.Server.Vault.UnitTests;

/// <summary>
/// Covers the one thing that makes a short-lived Vault token usable: the header is read per request, so a token
/// renewed by AppRole or Kubernetes auth takes effect without restarting the process.
/// </summary>
public sealed class VaultTokenHandlerTests : IDisposable
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
        var handler = new VaultTokenHandler(monitor) { InnerHandler = transport };
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://vault.test/v1/") };
        _httpClients.Add(httpClient);
        return httpClient;
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
            seen.Add(request.Headers.TryGetValues(VaultTokenHandler.TokenHeader, out var values)
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

        Assert.False(seen!.Headers.Contains(VaultTokenHandler.TokenHeader));
    }
}
