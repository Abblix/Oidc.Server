// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ReusePrevention;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ReusePrevention;

/// <summary>
/// Unit tests for <see cref="AuthorizationValueReuseDetector"/> covering the RFC 9700 Section 2.1.1
/// constant-value detection: a value reserved once is refused the next time, distinct values/kinds/clients stay
/// independent, and the whole mechanism is inert unless the detection interval is configured.
/// </summary>
public class AuthorizationValueReuseDetectorTests
{
    private const string CodeChallenge = "code_challenge";
    private const string Nonce = "nonce";

    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));

    private AuthorizationValueReuseDetector CreateDetector(TimeSpan? interval)
        => new(
            new DistributedReplayCache(
                new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
                _clock,
                "test:"),
            new EntityStorageKeyFactory(),
            Options.Create(new OidcOptions { PkceAndNonceReuseDetectionInterval = interval }),
            _clock);

    [Fact]
    public async Task Enabled_ReserveTwice_RefusesTheSecond()
    {
        var detector = CreateDetector(Interval);

        Assert.True(await detector.TryReserveAsync(SingleIssuer.Tenant, "c1", CodeChallenge, "value-1"));
        Assert.False(await detector.TryReserveAsync(SingleIssuer.Tenant, "c1", CodeChallenge, "value-1"));

        // A different value, a different kind, and a different client are all independent.
        Assert.True(await detector.TryReserveAsync(SingleIssuer.Tenant, "c1", CodeChallenge, "value-2"));
        Assert.True(await detector.TryReserveAsync(SingleIssuer.Tenant, "c1", Nonce, "value-1"));
        Assert.True(await detector.TryReserveAsync(SingleIssuer.Tenant, "c2", CodeChallenge, "value-1"));
    }

    /// <summary>
    /// Many requests presenting one value together: exactly one is told it is the first, because deciding and
    /// reserving are one step of the store.
    /// </summary>
    [Fact]
    public async Task Enabled_ManyFirstUsesTogether_ExactlyOneWins()
    {
        var detector = CreateDetector(Interval);

        var answers = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(
            () => detector.TryReserveAsync(SingleIssuer.Tenant, "c1", Nonce, "value-1"),
            TestContext.Current.CancellationToken)));

        Assert.Single(answers, answer => answer);
    }

    /// <summary>
    /// Each tenant reserves the values its clients present in a space of its own: a value one tenant's client used is
    /// fresh at another tenant's client of the same id, and still reused at its own.
    /// </summary>
    [Fact]
    public async Task AValueReservedAtOneTenant_IsFreshAtAnother_AndReusedAtItsOwn()
    {
        var detector = CreateDetector(Interval);
        var acme = new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com/acme") };
        var globex = new TenantDefinition { Id = "globex", Issuer = new Uri("https://auth.example.com/globex") };

        Assert.True(await detector.TryReserveAsync(acme, "c1", CodeChallenge, "value-1"));

        Assert.True(await detector.TryReserveAsync(globex, "c1", CodeChallenge, "value-1"));
        Assert.False(await detector.TryReserveAsync(acme, "c1", CodeChallenge, "value-1"));
    }

    [Fact]
    public async Task Disabled_IsInert()
    {
        var detector = CreateDetector(interval: null);

        // Nothing is reserved and nothing is refused while detection is off.
        Assert.True(await detector.TryReserveAsync(SingleIssuer.Tenant, "c1", CodeChallenge, "value-1"));
        Assert.True(await detector.TryReserveAsync(SingleIssuer.Tenant, "c1", CodeChallenge, "value-1"));
    }
}
