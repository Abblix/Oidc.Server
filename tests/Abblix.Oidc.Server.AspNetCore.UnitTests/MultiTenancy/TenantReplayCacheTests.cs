// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// Single-use token identifiers, reserved through the replay cache the server resolves under multi-tenancy.
/// </summary>
public sealed class TenantReplayCacheTests : IDisposable
{
    public void Dispose() => _provider.Dispose();

    private const string Jti = "client-chosen-jti";

    private readonly ServiceProvider _provider = new ServiceCollection()
        .AddServerStorage()
        .AddMultiTenancy(_ => { })
        .Services
        .BuildServiceProvider();

    private IReplayCache Cache => _provider.GetRequiredService<IReplayCache>();

    private DateTimeOffset ExpiresAt => _provider.GetRequiredService<TimeProvider>().GetUtcNow().AddMinutes(5);

    private void Enter(string? tenantId)
    {
        var context = new DefaultHttpContext();
        if (tenantId is not null)
        {
            context.Features.Set(new TenantContext
            {
                Tenant = new TenantDefinition { Id = tenantId, Issuer = $"https://auth.example.com/tenants/{tenantId}" },
            });
        }

        _provider.GetRequiredService<IHttpContextAccessor>().HttpContext = context;
    }

    [Fact]
    public void TheReplayCacheTheServerResolves_IsKeptPerTenant()
        => Assert.IsType<TenantReplayCache>(Cache);

    /// <summary>
    /// Two tenants' clients can present the same identifier; the first tenant to see it must not refuse the other's.
    /// </summary>
    [Fact]
    public async Task AnIdentifierSeenByOneTenant_IsFreshForAnother_AndAReplayForItself()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        Enter("acme");
        Assert.True(await Cache.TryReserveAsync(Jti, ExpiresAt, cancellationToken));

        Enter("globex");
        Assert.True(await Cache.TryReserveAsync(Jti, ExpiresAt, cancellationToken));

        Enter("acme");
        Assert.False(await Cache.TryReserveAsync(Jti, ExpiresAt, cancellationToken));
    }

    /// <summary>
    /// A release frees the releasing tenant's own reservation - and only that one.
    /// </summary>
    [Fact]
    public async Task AReleaseFreesTheTenantsOwnReservation_AndLeavesTheOthers()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        Enter("acme");
        Assert.True(await Cache.TryReserveAsync(Jti, ExpiresAt, cancellationToken));
        Enter("globex");
        Assert.True(await Cache.TryReserveAsync(Jti, ExpiresAt, cancellationToken));
        await Cache.ReleaseAsync(Jti, cancellationToken);
        Assert.True(await Cache.TryReserveAsync(Jti, ExpiresAt, cancellationToken));

        Enter("acme");
        Assert.False(await Cache.TryReserveAsync(Jti, ExpiresAt, cancellationToken));
    }

    /// <summary>
    /// Outside any tenant - a security event token receiver running beside the server - reservations still work,
    /// in a space apart from every tenant's.
    /// </summary>
    [Fact]
    public async Task OutsideAnyTenant_ReservationsWork_ApartFromTheTenants()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        Enter(null);
        Assert.True(await Cache.TryReserveAsync(Jti, ExpiresAt, cancellationToken));
        Assert.False(await Cache.TryReserveAsync(Jti, ExpiresAt, cancellationToken));

        Enter("acme");
        Assert.True(await Cache.TryReserveAsync(Jti, ExpiresAt, cancellationToken));
    }
}
