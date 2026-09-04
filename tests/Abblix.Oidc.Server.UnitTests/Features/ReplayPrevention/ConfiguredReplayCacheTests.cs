// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ReplayPrevention;

/// <summary>
/// A reservation must outlive the window in which the thing it names could still be accepted. A
/// reservation expiring first is a replay hole rather than a tidy cache, and it is silent: the
/// second presentation is accepted and nothing records that the first one existed.
/// </summary>
/// <remarks>
/// Two acceptance windows exist and they are reached by different paths. The JWT-bearer grant
/// honours this deployment's own setting; a client assertion is accepted on the security profile's
/// window and never reads that setting at all. So the retention has to cover the LARGER of the two,
/// and this class exists because taking whichever one happens to be set is indistinguishable from
/// covering both until the two disagree.
/// </remarks>
public class ConfiguredReplayCacheTests
{
    private static readonly DateTimeOffset Expiry = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// Records the deadline it was handed, which is what these cases are about. The class also emits
    /// the two events an operator's runbook keys off, and nothing here holds it to those.
    /// </summary>
    private sealed class RecordingCache : IReplayCache
    {
        public DateTimeOffset? Reserved { get; private set; }

        public Task<bool> TryReserveAsync(
            string identifier, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
        {
            Reserved = expiresAt;
            return Task.FromResult(true);
        }
    }

    private static async Task<DateTimeOffset> ReservedDeadline(TimeSpan? configured)
    {
        var inner = new RecordingCache();
        var cache = new ConfiguredReplayCache(
            NullLogger<ConfiguredReplayCache>.Instance,
            inner,
            new OptionsMonitorStub(new OidcOptions
            {
                JwtBearer = new JwtBearerOptions { ClockSkew = configured },
            }));

        Assert.True(await cache.TryReserveAsync("jti", Expiry, TestContext.Current.CancellationToken));

        return inner.Reserved!.Value;
    }

    /// <summary>
    /// The window a client assertion is accepted in, which no deployment setting can shorten because
    /// that path never reads the setting. This is the case that goes red if the retention is
    /// resolved from the configured value alone.
    /// </summary>
    private static TimeSpan AssertionWindow
        => SecurityProfileRequirements.Resolve(ClientSecurityProfile.None).DefaultClockSkew.Past;

    /// <summary>
    /// A deployment naming a window SHORTER than the assertion path accepts still retains for the
    /// longer one. Resolving from the setting alone would retain for the shorter window and leave
    /// the assertion replayable in the gap between the two.
    /// </summary>
    [Fact]
    public async Task AShorterConfiguredWindow_DoesNotShortenTheRetention()
    {
        var configured = AssertionWindow - TimeSpan.FromMinutes(1);

        var reserved = await ReservedDeadline(configured);

        Assert.True(
            reserved >= Expiry + AssertionWindow,
            $"retained until {reserved:O} while an assertion is accepted until "
            + $"{Expiry + AssertionWindow:O}");
    }

    /// <summary>
    /// And a deployment naming a LONGER one is not cut down to the profile's window, without which
    /// the case above would be satisfied by ignoring the setting entirely.
    /// </summary>
    [Fact]
    public async Task ALongerConfiguredWindow_IsHonoured()
    {
        var configured = AssertionWindow + TimeSpan.FromMinutes(1);

        var reserved = await ReservedDeadline(configured);

        Assert.Equal(Expiry + configured, reserved);
    }

    /// <summary>
    /// Setting nothing leaves the profile's window, which is what the bearer grant resolves to as
    /// well. Without this case both cases above could be satisfied by a class that always adds the
    /// configured value and treats its absence as zero.
    /// </summary>
    [Fact]
    public async Task NothingConfigured_RetainsForTheProfilesWindow()
    {
        var reserved = await ReservedDeadline(null);

        Assert.Equal(Expiry + AssertionWindow, reserved);
    }

    /// <summary>
    /// And the window this is measured against is not zero, or every case here would be satisfied by
    /// a class that retains for exactly the expiry it was handed.
    /// </summary>
    [Fact]
    public void TheAssertionWindow_IsNotZero()
    {
        Assert.True(AssertionWindow > TimeSpan.Zero);
    }

    private sealed class OptionsMonitorStub(OidcOptions value) : IOptionsMonitor<OidcOptions>
    {
        public OidcOptions CurrentValue => value;

        public OidcOptions Get(string? name) => value;

        public IDisposable? OnChange(Action<OidcOptions, string?> listener) => null;
    }
}
