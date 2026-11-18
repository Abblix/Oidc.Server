// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ReusePrevention;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ReusePrevention;

/// <summary>
/// Unit tests for <see cref="AuthorizationValueReuseDetector"/> covering the RFC 9700 Section 2.1.1
/// constant-value detection: a value reserved once is reported as reused and refused a second reservation,
/// distinct values/kinds/clients stay independent, and the whole mechanism is inert unless the detection interval
/// is configured.
/// </summary>
public class AuthorizationValueReuseDetectorTests
{
    private const string CodeChallenge = "code_challenge";
    private const string Nonce = "nonce";

    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

    private static IEntityStorage Storage()
        => new DistributedCacheStorage(
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
            new JsonBinarySerializer());

    private static AuthorizationValueReuseDetector CreateDetector(TimeSpan? interval, IEntityStorage? storage = null)
        => new(
            storage ?? Storage(),
            new EntityStorageKeyFactory(),
            Options.Create(new OidcOptions { PkceAndNonceReuseDetectionInterval = interval }));

    [Fact]
    public async Task Enabled_ReserveThenCheck_ReportsReused()
    {
        var detector = CreateDetector(Interval);

        // A value not yet reserved is fresh; after reserving, the same value is flagged as reused.
        Assert.False(await detector.IsReusedAsync(SingleIssuer.Tenant, "c1", CodeChallenge, "value-1"));
        Assert.True(await detector.TryReserveAsync(SingleIssuer.Tenant, "c1", CodeChallenge, "value-1"));
        Assert.True(await detector.IsReusedAsync(SingleIssuer.Tenant, "c1", CodeChallenge, "value-1"));
        Assert.False(await detector.TryReserveAsync(SingleIssuer.Tenant, "c1", CodeChallenge, "value-1"));

        // A different value, a different kind, and a different client are all independent.
        Assert.False(await detector.IsReusedAsync(SingleIssuer.Tenant, "c1", CodeChallenge, "value-2"));
        Assert.False(await detector.IsReusedAsync(SingleIssuer.Tenant, "c1", Nonce, "value-1"));
        Assert.False(await detector.IsReusedAsync(SingleIssuer.Tenant, "c2", CodeChallenge, "value-1"));
    }

    /// <summary>
    /// Two requests presenting one value for the first time together: one is told it is the first. The other runs
    /// whole inside this one's step on the record, whether that step reads it or claims it, so a detector that reads
    /// and then writes tells both they are first.
    /// </summary>
    [Fact]
    public async Task Enabled_TwoOverlappingFirstUses_OneWins()
    {
        var hash = Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes("value-1")));
        var overlapping = new LetsAnotherCallerIn(
            Storage(),
            new EntityStorageKeyFactory().AuthorizationValueReuseKey(SingleIssuer.Tenant, "c1", Nonce, hash));
        var detector = CreateDetector(Interval, overlapping.Storage);

        bool? other = null;
        var ran = 0;
        async Task RunTheOther()
        {
            if (Interlocked.Exchange(ref ran, 1) == 0)
                other = await detector.TryReserveAsync(SingleIssuer.Tenant, "c1", Nonce, "value-1");
        }

        overlapping.OnNextReadOf(RunTheOther);
        overlapping.OnNextClaimOf(RunTheOther);

        var mine = await detector.TryReserveAsync(SingleIssuer.Tenant, "c1", Nonce, "value-1");

        Assert.Single([mine, other], first => first == true);
        Assert.Single([mine, other], first => first == false);
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

        Assert.False(await detector.IsReusedAsync(globex, "c1", CodeChallenge, "value-1"));
        Assert.True(await detector.IsReusedAsync(acme, "c1", CodeChallenge, "value-1"));
    }

    [Fact]
    public async Task Disabled_IsInert()
    {
        var detector = CreateDetector(interval: null);

        // Nothing is reserved and nothing is flagged while detection is off.
        Assert.True(await detector.TryReserveAsync(SingleIssuer.Tenant, "c1", CodeChallenge, "value-1"));
        Assert.True(await detector.TryReserveAsync(SingleIssuer.Tenant, "c1", CodeChallenge, "value-1"));
        Assert.False(await detector.IsReusedAsync(SingleIssuer.Tenant, "c1", CodeChallenge, "value-1"));
    }
}
