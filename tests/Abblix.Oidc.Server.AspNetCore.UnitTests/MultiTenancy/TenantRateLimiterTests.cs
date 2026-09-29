// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.RateLimiting;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// The budgets the server keeps per caller, as the server resolves them under multi-tenancy.
/// </summary>
public sealed class TenantRateLimiterTests : IDisposable
{
    private const string Address = "203.0.113.7";
    private const string ClientId = "client-1";

    private readonly ServiceProvider _provider;

    public TenantRateLimiterTests()
    {
        var services = new ServiceCollection().AddServerStorage().AddIntrospection();
        services.Configure<OidcOptions>(options =>
        {
            options.AuthenticationFailureLimit.PermitLimit = 1;
            options.CallerRateLimit.PermitLimit = 1;
        });
        _provider = services.AddMultiTenancy(_ => { }).BuildServiceProvider();
    }

    public void Dispose() => _provider.Dispose();

    private PartitionedRateLimiter<string> Failures
        => _provider.GetRequiredKeyedService<PartitionedRateLimiter<string>>(CallerRateLimiters.AuthenticationFailures);

    private PartitionedRateLimiter<(string ClientId, string? Source)> Introspection
        => _provider.GetRequiredKeyedService<PartitionedRateLimiter<(string ClientId, string? Source)>>(
            CallerRateLimiters.Introspection);

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

    /// <summary>
    /// A source that spent one tenant's budget of failed authentications still has the other tenant's.
    /// </summary>
    [Fact]
    public void FailuresFromOneAddress_SpendOnlyTheTenantTheyWereAgainst()
    {
        Enter("acme");
        Assert.True(Failures.AttemptAcquire(Address).IsAcquired);
        Assert.False(Failures.AttemptAcquire(Address).IsAcquired);

        Enter("globex");
        Assert.True(Failures.AttemptAcquire(Address).IsAcquired);
    }

    /// <summary>
    /// Two tenants' clients may share an id; one's introspection calls do not spend the other's budget.
    /// </summary>
    [Fact]
    public void CallsOfOneTenantsClient_SpendOnlyThatTenantsBudget()
    {
        Enter("acme");
        Assert.True(Introspection.AttemptAcquire((ClientId, null)).IsAcquired);
        Assert.False(Introspection.AttemptAcquire((ClientId, null)).IsAcquired);

        Enter("globex");
        Assert.True(Introspection.AttemptAcquire((ClientId, null)).IsAcquired);
    }

    /// <summary>
    /// The server spends its budgets synchronously, but a host may wait for a permit or read what is left; both
    /// answer for the current tenant too.
    /// </summary>
    [Fact]
    public async System.Threading.Tasks.Task WaitingForAPermit_AndReadingWhatIsLeft_AreThePerTenantBudget()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        Enter("acme");
        using (var lease = await Failures.AcquireAsync(Address, cancellationToken: cancellationToken))
            Assert.True(lease.IsAcquired);
        Assert.Equal(0, Failures.GetStatistics(Address)?.CurrentAvailablePermits);

        Enter("globex");
        Assert.Equal(1, Failures.GetStatistics(Address)?.CurrentAvailablePermits);
    }

    [Fact]
    public void WithoutATenant_TheBudgetIsNotSpent_ButRefused()
    {
        Enter(null);

        Assert.Throws<InvalidOperationException>(() => Failures.AttemptAcquire(Address));
        Assert.Throws<InvalidOperationException>(() => Introspection.AttemptAcquire((ClientId, null)));
    }

    /// <summary>
    /// The limiter a tenant budget wraps was built for it alone and holds the timers of its windows, so it goes
    /// when the wrapper goes, whichever way the container disposes it.
    /// </summary>
    [Fact]
    public void DisposingTheBudget_DisposesTheLimiterItWraps()
    {
        var inner = PartitionedRateLimiter.Create<string, string>(key => RateLimitPartition.GetNoLimiter(key));

        new TenantAddressRateLimiter(inner, new HttpContextTenantAccessor(new HttpContextAccessor())).Dispose();

        Assert.Throws<ObjectDisposedException>(() => inner.AttemptAcquire(Address));
    }

    [Fact]
    public async System.Threading.Tasks.Task DisposingTheBudgetAsynchronously_DisposesTheLimiterItWraps()
    {
        var inner = PartitionedRateLimiter.Create<string, string>(key => RateLimitPartition.GetNoLimiter(key));

        await new TenantAddressRateLimiter(inner, new HttpContextTenantAccessor(new HttpContextAccessor())).DisposeAsync();

        Assert.Throws<ObjectDisposedException>(() => inner.AttemptAcquire(Address));
    }

    /// <summary>
    /// An endpoint the host did not enable registers no budget, and multi-tenancy asks for none.
    /// </summary>
    [Fact]
    public void ABudgetOfAnEndpointNotEnabled_IsNotRequired()
        => Assert.Null(_provider.GetKeyedService<PartitionedRateLimiter<(string ClientId, string? Source)>>(
            CallerRateLimiters.Revocation));
}
