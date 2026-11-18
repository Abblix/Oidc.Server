// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A trusted issuer of the JWT bearer grant or of software statements that is a tenant this server serves is never
/// trusted, since its revoked tokens would pass; the server starts and warns that the entry has no effect.
/// </summary>
public sealed class TrustedTenantIssuerTests
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";

    // The event the warning is logged under
    private const int TrustedIssuerIsServedTenant = 10760;

    /// <summary>
    /// A server listing its tenant as a trusted issuer starts and warns once for each list naming it; the same server
    /// trusting another issuer starts without the warning.
    /// </summary>
    [Theory]
    [InlineData(true, false, 1)]
    [InlineData(false, true, 1)]
    [InlineData(true, true, 2)]
    [InlineData(false, false, 0)]
    public async Task ATenantListedAsATrustedIssuer_IsWarnedOf(bool bearer, bool statements, int warnings)
    {
        var logs = new RecordingLogs();
        await using var app = await BuildAsync(logs, bearer ? Host + Acme : Host + Globex, statements ? Host + Acme : Host + Globex);

        await app.StartAsync(TestContext.Current.CancellationToken);

        Assert.Equal(warnings, logs.EventIds.Count(id => id == TrustedIssuerIsServedTenant));
    }

    private static async Task<WebApplication> BuildAsync(RecordingLogs logs, string bearerIssuer, string statementIssuer)
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.AddProvider(logs);
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(options =>
        {
            options.EnabledEndpoints = OidcEndpoints.Base;
            options.Tenants.Add(new TenantDefinition
            {
                Id = "acme",
                Issuer = new Uri(Host + Acme),
                SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
            });
            options.JwtBearer = new JwtBearerOptions
            {
                TrustedIssuers = [new TrustedIssuer { Issuer = bearerIssuer, JwksUri = new Uri("https://idp.example.com/jwks") }],
            };
            options.SoftwareStatement.TrustedIssuers =
                [new TrustedIssuer { Issuer = statementIssuer, JwksUri = new Uri("https://idp.example.com/jwks") }];
        });

        var app = builder.Build();
        app.UseMultiTenancy();
        app.MapOidcEndpoints();
        return app;
    }

    /// <summary>
    /// Keeps the event id of every entry logged.
    /// </summary>
    private sealed class RecordingLogs : ILoggerProvider
    {
        private readonly ConcurrentQueue<int> _eventIds = new();

        public IReadOnlyCollection<int> EventIds => _eventIds;

        public ILogger CreateLogger(string categoryName) => new Recording(_eventIds);

        public void Dispose()
        {
            // Nothing is held
        }

        private sealed class Recording(ConcurrentQueue<int> eventIds) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
                => eventIds.Enqueue(eventId.Id);
        }
    }
}
