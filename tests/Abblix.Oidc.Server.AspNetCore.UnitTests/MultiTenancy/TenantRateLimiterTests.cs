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


namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// The budgets the server keeps per caller, as the server resolves them under multi-tenancy.
/// </summary>
public sealed class TenantRateLimiterTests : IDisposable
{
    /// <summary>
    /// Registers nothing that serves a lone tenant, so the accessor reads only the tenant a request was resolved to.
    /// </summary>
    private static readonly IServiceProvider NoLoneTenant = new ServiceCollection().BuildServiceProvider();

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
        _provider = services.ServeTenants().BuildServiceProvider();
    }

    public void Dispose() => _provider.Dispose();

    private PartitionedRateLimiter<string> Failures
        => _provider.GetRequiredKeyedService<PartitionedRateLimiter<string>>(CallerRateLimiters.AuthenticationFailures);

    private PartitionedRateLimiter<(string ClientId, string? Source)> Introspection
        => _provider.GetRequiredKeyedService<PartitionedRateLimiter<(string ClientId, string? Source)>>(
            CallerRateLimiters.Introspection);

    private void Enter(string? tenantId, string generation = "")
    {
        var context = new DefaultHttpContext();
        if (tenantId is not null)
        {
            context.Features.Set(new TenantContext
            {
                Tenant = new TenantDefinition
                {
                    Id = tenantId,
                    Issuer = new Uri($"https://auth.example.com/tenants/{tenantId}"),
                    Generation = generation,
                },
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
    /// A tenant created again under the id of one removed starts with a budget of its own, not with what the
    /// removed one had spent.
    /// </summary>
    [Fact]
    public void ATenantCreatedAgainUnderAnId_StartsWithABudgetOfItsOwn()
    {
        Enter("acme", generation: "1");
        Assert.True(Introspection.AttemptAcquire((ClientId, null)).IsAcquired);
        Assert.False(Introspection.AttemptAcquire((ClientId, null)).IsAcquired);

        Enter("acme", generation: "2");
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
    /// Each tenant's limiter was built for the budget alone and holds the timers of its windows, so it goes when
    /// the budget goes, whichever way the container disposes it.
    /// </summary>
    [Fact]
    public void DisposingTheBudget_DisposesEveryTenantsLimiter()
    {
        var (budget, built) = BudgetOverNewLimiters();

        budget.Dispose();

        Assert.All(built, limiter => Assert.Throws<ObjectDisposedException>(() => limiter.AttemptAcquire(Address)));
    }

    [Fact]
    public async System.Threading.Tasks.Task DisposingTheBudgetAsynchronously_DisposesEveryTenantsLimiter()
    {
        var (budget, built) = BudgetOverNewLimiters();

        await budget.DisposeAsync();

        Assert.All(built, limiter => Assert.Throws<ObjectDisposedException>(() => limiter.AttemptAcquire(Address)));
    }

    /// <summary>
    /// The limiter of a tenant the store no longer holds is disposed once the tenant is released, its timer with it,
    /// while a request still holding the tenant spends against no limiter rather than build one again.
    /// </summary>
    [Fact]
    public async Task TheLimiterOfAReleasedTenant_IsDisposed()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new Microsoft.Extensions.Time.Testing.FakeTimeProvider();
        var declared = new OidcOptions
        {
            Tenants = [new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com/tenants/acme") }],
        };
        var catalog = new StoreTenantCatalog(
            Microsoft.Extensions.Logging.Abstractions.NullLogger<StoreTenantCatalog>.Instance,
            new OptionsTenantStore(Microsoft.Extensions.Options.Options.Create(declared)),
            [],
            [],
            [],
            Microsoft.Extensions.Options.Options.Create(declared),
            time);
        await catalog.RefreshAsync(ct);

        var built = new System.Collections.Generic.List<PartitionedRateLimiter<string>>();
        using var budget = new TenantPartitionedRateLimiter<string>(
            () =>
            {
                var limiter = PartitionedRateLimiter.Create<string, string>(RateLimitPartition.GetNoLimiter);
                built.Add(limiter);
                return limiter;
            },
            new HttpContextTenantAccessor(new HttpContextAccessor { HttpContext = InTenant("acme") }, NoLoneTenant),
            catalog);
        budget.AttemptAcquire(Address).Dispose();

        declared.Tenants.Clear();
        await catalog.RefreshAsync(ct);
        built[0].AttemptAcquire(Address).Dispose();

        time.Advance(declared.RefreshTenantsEvery);
        await catalog.RefreshAsync(ct);
        Assert.Throws<ObjectDisposedException>(() => built[0].AttemptAcquire(Address));
        budget.AttemptAcquire(Address).Dispose();
        Assert.Single(built);
    }

    /// <summary>
    /// A tenant released while its limiter is being built has that limiter disposed at once, so the request that
    /// built it spends against no limiter rather than fail on a disposed one.
    /// </summary>
    [Fact]
    public async Task ATenantReleasedWhileItsLimiterIsBuilt_SpendsAgainstNoLimiter()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new Microsoft.Extensions.Time.Testing.FakeTimeProvider();
        var declared = new OidcOptions
        {
            Tenants = [new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com/tenants/acme") }],
        };
        var catalog = new StoreTenantCatalog(
            Microsoft.Extensions.Logging.Abstractions.NullLogger<StoreTenantCatalog>.Instance,
            new OptionsTenantStore(Microsoft.Extensions.Options.Options.Create(declared)),
            [],
            [],
            [],
            Microsoft.Extensions.Options.Options.Create(declared),
            time);
        await catalog.RefreshAsync(ct);
        declared.Tenants.Clear();
        await catalog.RefreshAsync(ct);

        using var budget = new TenantPartitionedRateLimiter<string>(
            () =>
            {
                // The reading that releases the tenant lands while the limiter is being built
                time.Advance(declared.RefreshTenantsEvery);
                catalog.RefreshAsync(ct).GetAwaiter().GetResult();
                return PartitionedRateLimiter.Create<string, string>(RateLimitPartition.GetNoLimiter);
            },
            new HttpContextTenantAccessor(new HttpContextAccessor { HttpContext = InTenant("acme") }, NoLoneTenant),
            catalog);

        using var lease = budget.AttemptAcquire(Address);
        Assert.True(lease.IsAcquired);
    }

    /// <summary>
    /// A budget that has built a limiter for two tenants, and those limiters.
    /// </summary>
    private static (TenantPartitionedRateLimiter<string> Budget, System.Collections.Generic.List<PartitionedRateLimiter<string>> Built)
        BudgetOverNewLimiters()
    {
        var built = new System.Collections.Generic.List<PartitionedRateLimiter<string>>();
        var httpContextAccessor = new HttpContextAccessor();
        var budget = new TenantPartitionedRateLimiter<string>(
            () =>
            {
                var limiter = PartitionedRateLimiter.Create<string, string>(key => RateLimitPartition.GetNoLimiter(key));
                built.Add(limiter);
                return limiter;
            },
            new HttpContextTenantAccessor(httpContextAccessor, NoLoneTenant),
            Moq.Mock.Of<ITenantCatalog>());

        foreach (var tenantId in new[] { "acme", "globex" })
        {
            httpContextAccessor.HttpContext = InTenant(tenantId);
            budget.AttemptAcquire(Address).Dispose();
        }

        Assert.Equal(2, built.Count);
        return (budget, built);
    }

    /// <summary>
    /// A host's own limiter partitions by the address it was written for: each tenant gets one of its own, built
    /// the way the host registered it under the key of one tenant's budget, rather than one shared limiter seeing a
    /// key the host never produced.
    /// </summary>
    [Fact]
    public void AHostsOwnLimiter_IsBuiltPerTenant_AndSeesTheAddressUnchanged()
    {
        var built = 0;
        var seen = new System.Collections.Generic.List<string>();
        var services = new ServiceCollection();
        services.AddKeyedTransient<PartitionedRateLimiter<string>>(
            TenantServiceKeys.PerTenant(CallerRateLimiters.AuthenticationFailures),
            (_, _) =>
            {
                built++;
                return PartitionedRateLimiter.Create<string, string>(address =>
                {
                    seen.Add(address);
                    return RateLimitPartition.GetNoLimiter(address);
                });
            });
        using var provider = services.AddServerStorage().ServeTenants().BuildServiceProvider();
        var accessor = provider.GetRequiredService<IHttpContextAccessor>();
        var failures = provider.GetRequiredKeyedService<PartitionedRateLimiter<string>>(
            CallerRateLimiters.AuthenticationFailures);

        foreach (var tenantId in new[] { "acme", "globex", "acme" })
        {
            accessor.HttpContext = InTenant(tenantId);
            failures.AttemptAcquire(Address).Dispose();
        }

        Assert.Equal(2, built);
        Assert.All(seen, address => Assert.Equal(Address, address));
    }

    /// <summary>
    /// A host's factory that hands every call the same limiter would let one tenant's callers spend another's
    /// budget, so the second tenant it is handed to is refused rather than served from the first one's limiter.
    /// </summary>
    [Fact]
    public void AHostsFactoryHandingOutOneLimiter_IsRefusedForTheSecondTenant()
    {
        var shared = PartitionedRateLimiter.Create<string, string>(address => RateLimitPartition.GetNoLimiter(address));
        var services = new ServiceCollection();
        services.AddKeyedTransient<PartitionedRateLimiter<string>>(
            TenantServiceKeys.PerTenant(CallerRateLimiters.AuthenticationFailures), (_, _) => shared);
        using var provider = services.AddServerStorage().ServeTenants().BuildServiceProvider();
        var accessor = provider.GetRequiredService<IHttpContextAccessor>();
        var failures = provider.GetRequiredKeyedService<PartitionedRateLimiter<string>>(
            CallerRateLimiters.AuthenticationFailures);

        accessor.HttpContext = InTenant("acme");
        failures.AttemptAcquire(Address).Dispose();

        accessor.HttpContext = InTenant("globex");
        Assert.Throws<InvalidOperationException>(() => failures.AttemptAcquire(Address));
    }

    /// <summary>
    /// The same factory met by two tenants' first calls at once: both builds are in progress together, and still
    /// one of the two is refused, since neither tenant's limiter is finished when the other one checks.
    /// </summary>
    /// <remarks>
    /// Which build finishes first is the scheduler's choice and cannot be held from the factory, so the meeting is
    /// repeated: a check that reads only finished builds lets both through in a few of every hundred.
    /// </remarks>
    [Fact]
    public async System.Threading.Tasks.Task AFactoryHandingOutOneLimiter_IsRefusedWhenTwoTenantsBuildAtOnce()
    {
        const int meetings = 500;
        var bothServed = 0;
        for (var meeting = 0; meeting < meetings; meeting++)
        {
            if (await BothServedWhenBuildingAtOnceAsync())
                bothServed++;
        }

        Assert.Equal(0, bothServed);
    }

    private static async System.Threading.Tasks.Task<bool> BothServedWhenBuildingAtOnceAsync()
    {
        var shared = PartitionedRateLimiter.Create<string, string>(address => RateLimitPartition.GetNoLimiter(address));
        var arrived = 0;
        using var bothBuilding = new System.Threading.ManualResetEventSlim();
        var httpContextAccessor = new HttpContextAccessor();
        var budget = new TenantPartitionedRateLimiter<string>(
            () =>
            {
                if (System.Threading.Interlocked.Increment(ref arrived) == 2)
                    bothBuilding.Set();

                bothBuilding.Wait(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
                return shared;
            },
            new HttpContextTenantAccessor(httpContextAccessor, NoLoneTenant),
            Moq.Mock.Of<ITenantCatalog>());

        var calls = new[] { "acme", "globex" }.Select(tenantId => System.Threading.Tasks.Task.Run(() =>
        {
            httpContextAccessor.HttpContext = InTenant(tenantId);
            budget.AttemptAcquire(Address).Dispose();
        }, TestContext.Current.CancellationToken)).ToArray();

        try
        {
            await System.Threading.Tasks.Task.WhenAll(calls);
        }
        catch (InvalidOperationException)
        {
            // The refusal expected of one of the two
        }

        Assert.Equal(2, arrived);
        return calls.All(call => call.IsCompletedSuccessfully);
    }

    /// <summary>
    /// A host's limiter registered by its type is built per tenant in the same way.
    /// </summary>
    [Fact]
    public void AHostsLimiterRegisteredByType_IsBuiltPerTenant()
    {
        var log = new HostLimiterLog();
        var services = new ServiceCollection().AddSingleton(log);
        services.AddKeyedTransient<PartitionedRateLimiter<string>, HostLimiter>(
            TenantServiceKeys.PerTenant(CallerRateLimiters.AuthenticationFailures));
        using var provider = services.AddServerStorage().ServeTenants().BuildServiceProvider();
        var accessor = provider.GetRequiredService<IHttpContextAccessor>();
        var failures = provider.GetRequiredKeyedService<PartitionedRateLimiter<string>>(
            CallerRateLimiters.AuthenticationFailures);

        foreach (var tenantId in new[] { "acme", "globex", "acme" })
        {
            accessor.HttpContext = InTenant(tenantId);
            failures.AttemptAcquire(Address).Dispose();
        }

        Assert.Equal(2, log.Built);
        Assert.Equal([Address, Address, Address], log.Seen);
    }

    /// <summary>
    /// Two first calls of one tenant arriving together build one limiter between them; a second one would be
    /// dropped with its window timers still running.
    /// </summary>
    [Fact]
    public async System.Threading.Tasks.Task TwoFirstCallsOfOneTenant_BuildOneLimiter()
    {
        var built = 0;
        using var secondArrived = new System.Threading.ManualResetEventSlim();
        var httpContextAccessor = new HttpContextAccessor { HttpContext = InTenant("acme") };
        using var budget = new TenantPartitionedRateLimiter<string>(
            () =>
            {
                if (System.Threading.Interlocked.Increment(ref built) == 2)
                    secondArrived.Set();

                // Long enough for the other call to reach the build too, unless it is held off
                secondArrived.Wait(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
                return PartitionedRateLimiter.Create<string, string>(key => RateLimitPartition.GetNoLimiter(key));
            },
            new HttpContextTenantAccessor(httpContextAccessor, NoLoneTenant),
            Moq.Mock.Of<ITenantCatalog>());

        await System.Threading.Tasks.Task.WhenAll(
            System.Threading.Tasks.Task.Run(() => budget.AttemptAcquire(Address).Dispose(), TestContext.Current.CancellationToken),
            System.Threading.Tasks.Task.Run(() => budget.AttemptAcquire(Address).Dispose(), TestContext.Current.CancellationToken));

        Assert.Equal(1, built);
    }

    /// <summary>
    /// A limiter for one tenant's budget registered as a ready instance, or as a singleton, is one limiter handed to
    /// every tenant, which would let one tenant's callers spend another's budget, so the second tenant it is handed
    /// to is refused.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AHostsLimiterRegisteredOnceForEveryTenant_IsRefusedForTheSecondTenant(bool asAnInstance)
    {
        var services = new ServiceCollection();
        var perTenant = TenantServiceKeys.PerTenant(CallerRateLimiters.AuthenticationFailures);
        if (asAnInstance)
        {
            services.AddKeyedSingleton(
                perTenant,
                PartitionedRateLimiter.Create<string, string>(address => RateLimitPartition.GetNoLimiter(address)));
        }
        else
        {
            services.AddKeyedSingleton<PartitionedRateLimiter<string>>(
                perTenant,
                (_, _) => PartitionedRateLimiter.Create<string, string>(address => RateLimitPartition.GetNoLimiter(address)));
        }

        using var provider = services.AddServerStorage().ServeTenants().BuildServiceProvider();
        var accessor = provider.GetRequiredService<IHttpContextAccessor>();
        var failures = provider.GetRequiredKeyedService<PartitionedRateLimiter<string>>(
            CallerRateLimiters.AuthenticationFailures);

        accessor.HttpContext = InTenant("acme");
        failures.AttemptAcquire(Address).Dispose();

        accessor.HttpContext = InTenant("globex");
        Assert.Throws<InvalidOperationException>(() => failures.AttemptAcquire(Address));
    }

    private static DefaultHttpContext InTenant(string tenantId)
    {
        var context = new DefaultHttpContext();
        context.Features.Set(new TenantContext
        {
            Tenant = new TenantDefinition { Id = tenantId, Issuer = new Uri($"https://auth.example.com/tenants/{tenantId}") },
        });
        return context;
    }

    /// <summary>
    /// An endpoint the host did not enable registers no budget, and multi-tenancy asks for none.
    /// </summary>
    [Fact]
    public void ABudgetOfAnEndpointNotEnabled_IsNotRequired()
        => Assert.Null(_provider.GetKeyedService<PartitionedRateLimiter<(string ClientId, string? Source)>>(
            CallerRateLimiters.Revocation));
}
