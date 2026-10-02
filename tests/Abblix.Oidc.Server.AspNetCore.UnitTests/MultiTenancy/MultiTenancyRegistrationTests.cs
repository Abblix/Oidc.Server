// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.RateLimiting;
using System.Threading.Tasks;
using Abblix.DependencyInjection;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// What <see cref="MultiTenancyExtensions.AddMultiTenancy"/> puts in the container, the issuer a request gets
/// through it, and the tenant lists startup refuses.
/// </summary>
public partial class MultiTenancyRegistrationTests
{
    private const string AcmeIssuer = "https://auth.example.com/tenants/acme";

    private static readonly TenantDefinition Acme = new() { Id = "acme", Issuer = AcmeIssuer };

    private static ServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();

        // The library's own issuer registration, not a stand-in, since it is what AddMultiTenancy has to win over.
        services.AddIssuer();
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));

        return services.BuildServiceProvider();
    }

    private static void EnterTenant(IServiceProvider provider, TenantDefinition? tenant)
    {
        var context = new DefaultHttpContext();
        if (tenant is not null)
            context.Features.Set(new TenantContext { Tenant = tenant });

        provider.GetRequiredService<IHttpContextAccessor>().HttpContext = context;
    }

    [Fact]
    public void UnderATenant_TheIssuerIsTheOneItDeclares()
    {
        using var provider = BuildProvider();
        EnterTenant(provider, Acme);

        Assert.Equal(AcmeIssuer, provider.GetRequiredService<IIssuerProvider>().GetIssuer());
    }

    /// <summary>
    /// Multi-tenancy keeps each tenant's data apart by wrapping the storage the server registered, so a call
    /// placed before that storage would leave it shared - it is refused, naming the order.
    /// </summary>
    [Fact]
    public void AddMultiTenancy_BeforeTheServersStorage_IsRefused()
    {
        var services = new ServiceCollection();

        var refusal = Assert.Throws<InvalidOperationException>(
            () => services.AddMultiTenancy(options => options.Tenants.Add(Acme)));
        Assert.Contains("after AddOidcServices()", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The refusal names each service it finds missing, the per-caller budgets registered under a key included:
    /// storage in place but client authentication not yet registered is still the wrong order.
    /// </summary>
    [Fact]
    public void AddMultiTenancy_BeforeTheFailureBudget_IsRefused_NamingIt()
    {
        var services = new ServiceCollection()
            .AddLogging()
            .AddDistributedMemoryCache()
            .AddCommonServices()
            .AddReplayPrevention();

        var refusal = Assert.Throws<InvalidOperationException>(
            () => services.AddMultiTenancy(options => options.Tenants.Add(Acme)));
        Assert.Contains(CallerRateLimiters.AuthenticationFailures, refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A second call would wrap the storage again and change every key it holds, losing what was stored
    /// before, so it is refused.
    /// </summary>
    [Fact]
    public void ASecondCallToAddMultiTenancy_IsRefused()
    {
        var services = new ServiceCollection().AddServerStorage();
        services.AddMultiTenancy(options => options.Tenants.Add(Acme));

        var refusal = Assert.Throws<InvalidOperationException>(
            () => services.AddMultiTenancy(options => options.Tenants.Add(Acme)));
        Assert.Contains("already", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A host wrapping the storage itself after multi-tenancy is refused too, and told what to move rather than
    /// that something replaced the storage.
    /// </summary>
    [Fact]
    public void AStorageDecoratedAfterMultiTenancy_IsRefused_NamingTheOrder()
    {
        var services = new ServiceCollection().AddServerStorage();
        services.AddMultiTenancy(options => options.Tenants.Add(Acme));
        services.Decorate<IEntityStorage, PassThroughStorage>();
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains("registered or decorated after", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>A host's own storage wrapper, adding nothing.</summary>
    private sealed class PassThroughStorage(IEntityStorage inner) : IEntityStorage
    {
        public Task SetAsync<T>(string key, T value, StorageOptions options, System.Threading.CancellationToken? token = null)
            => inner.SetAsync(key, value, options, token);

        public Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, System.Threading.CancellationToken? token = null)
            => inner.GetAsync<T>(key, removeOnRetrieval, token);

        public Task<bool> TrySetIfAbsentAsync<T>(
            string key, T value, StorageOptions options, System.Threading.CancellationToken? token = null)
            => inner.TrySetIfAbsentAsync(key, value, options, token);

        public Task RemoveAsync(string key, System.Threading.CancellationToken? token = null)
            => inner.RemoveAsync(key, token);
    }

    /// <summary>
    /// The server's own mutual-TLS address, or its fixed aliases, name one address for every tenant, which no
    /// request can tell apart, so startup refuses them under multi-tenancy.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ServerWideMutualTlsAddresses_AreRefusedAtStartup(bool aliases)
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>().Configure(options =>
        {
            if (aliases)
                options.Discovery.MtlsEndpointAliases = new MtlsAliasesOptions { TokenEndpoint = new Uri("https://mtls.example.com/token") };
            else
                options.Discovery.MtlsBaseUri = new Uri("https://mtls.example.com");
        });
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
        Assert.Contains(
            aliases ? nameof(DiscoveryOptions.MtlsEndpointAliases) : nameof(DiscoveryOptions.MtlsBaseUri),
            refusal.Message,
            StringComparison.Ordinal);
    }

    public static TheoryData<TenantDefinition, string> TenantsTheServersChecksRefuse => new()
    {
        {
            new TenantDefinition
            {
                Id = "acme",
                Issuer = AcmeIssuer,
                DefaultResourceIndicator = new Uri("https://api.acme.example"),
            },
            nameof(OidcOptions.DefaultResourceIndicator)
        },
        {
            new TenantDefinition
            {
                Id = "acme",
                Issuer = AcmeIssuer,
                DefaultSecurityProfile = ClientSecurityProfile.Fapi2,
                Clients = [new ClientInfo("public") { TokenEndpointAuthMethod = ClientAuthenticationMethods.None }],
            },
            "Client 'public'"
        },
        {
            new TenantDefinition
            {
                Id = "acme",
                Issuer = AcmeIssuer,
                Clients = [new ClientInfo("App"), new ClientInfo("app")],
            },
            "2 clients are configured under the id 'App' and 'app'"
        },
        {
            new TenantDefinition
            {
                Id = "acme",
                Issuer = AcmeIssuer,
                Resources = [new ResourceDefinition(new Uri("api", UriKind.Relative))],
            },
            "The resource 'api' must be named by an absolute URI"
        },
    };

    /// <summary>
    /// What a tenant declares passes the checks the server's own settings pass at startup, so a tenant's mistake is
    /// refused there, naming the tenant, rather than surfacing on the first request that meets it.
    /// </summary>
    [Theory]
    [MemberData(nameof(TenantsTheServersChecksRefuse))]
    public void ATenantsSettings_PassTheServersOwnChecks(TenantDefinition tenant, string mistake)
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, DefaultResourceIndicatorValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, OidcOptionsSecurityProfileValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, ClientIdsOptionsValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, ResourceDefinitionsValidator>(),
        ]);
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(tenant));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains($"Tenant '{tenant.Id}': ", refusal.Message, StringComparison.Ordinal);
        Assert.Contains(mistake, refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A mistake in the server's own settings is reported by those settings, and does not hide what is wrong with the
    /// tenant list.
    /// </summary>
    [Fact]
    public void InvalidServerSettings_LeaveTheTenantListsOwnRefusalsVisible()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>().Configure(options => options.Issuer = "https://auth.example.com");
        services.AddServerStorage().AddMultiTenancy(options =>
        {
            options.Tenants.Add(Acme);
            options.Tenants.Add(new TenantDefinition { Id = "acme", Issuer = "https://auth.example.com/tenants/other" });
        });
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Equal(typeof(MultiTenancyOptions), refusal.OptionsType);
        Assert.Contains("The tenant id 'acme' is declared more than once.", refusal.Failures);
        Assert.DoesNotContain(refusal.Failures, failure => failure.Contains(nameof(OidcOptions.Issuer), StringComparison.Ordinal));
    }

    /// <summary>
    /// A pairwise client set for the whole server under multi-tenancy gets the refusal of server-wide clients, not a
    /// failure from asking a tenant's settings outside any tenant.
    /// </summary>
    [Fact]
    public void AServerWidePairwiseClient_UnderMultiTenancy_IsRefusedAsServerWide()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>().Configure(options =>
            options.Clients = [new ClientInfo("pairwise") { SubjectType = SubjectTypes.Pairwise }]);
        services.AddIssuer();
        services.AddClientInformation().AddUserInfo();
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
        Assert.Contains($"{nameof(OidcOptions)}.{nameof(OidcOptions.Clients)} applies to the whole server",
            refusal.Message, StringComparison.Ordinal);
    }

    public static TheoryData<Type, object> HostsOwnRegistries => new()
    {
        { typeof(IClientInfoProvider), Moq.Mock.Of<IClientInfoProvider>() },
        { typeof(IClientInfoManager), Moq.Mock.Of<IClientInfoManager>() },
        { typeof(IScopeManager), Moq.Mock.Of<IScopeManager>() },
        { typeof(IResourceManager), Moq.Mock.Of<IResourceManager>() },
        { typeof(ISubjectTypeConverter), Moq.Mock.Of<ISubjectTypeConverter>() },
        { typeof(IAuthServiceKeysProvider), Moq.Mock.Of<IAuthServiceKeysProvider>() },
    };

    /// <summary>
    /// A registry the host brings itself keeps one set of clients, scopes, resources or pairwise keys for every
    /// tenant, since nothing tells it which tenant a request is for, so startup refuses it, naming the service.
    /// </summary>
    [Theory]
    [MemberData(nameof(HostsOwnRegistries))]
    public void AHostsOwnRegistry_IsRefusedAtStartup(Type service, object registry)
    {
        var services = new ServiceCollection();
        services.AddSingleton(service, registry);
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains($"{service.Name} is the host's own", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A registry the host scopes to a request cannot be resolved at startup, and that failure is reported as the
    /// refusal, naming the service, rather than replacing every refusal of the tenant list with a container error.
    /// </summary>
    [Fact]
    public void AHostsRegistryScopedToARequest_IsRefusedAtStartup()
    {
        var services = new ServiceCollection();
        services.AddScoped(_ => Moq.Mock.Of<IClientInfoProvider>());
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains($"{nameof(IClientInfoProvider)} is the host's own", refusal.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TheServersOwnRegistries_PassTheStartupCheck(bool reloadableClients)
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        services.AddClientInformation().AddUserInfo();
        if (reloadableClients)
            services.AddReloadableClientInformation();
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        Assert.Single(provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value.Tenants);
    }

    [Fact]
    public void TheServersOwnComposition_PassesTheStartupCheck()
    {
        using var provider = BuildProvider();

        Assert.Single(provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value.Tenants);
    }

    /// <summary>
    /// A registration made after multi-tenancy replaces the wrapper silently, and every tenant would then read the
    /// others' data - so startup refuses it, naming the service.
    /// </summary>
    [Fact]
    public void AStorageReplacedAfterMultiTenancy_IsRefusedAtStartup()
    {
        var services = new ServiceCollection().AddServerStorage();
        services.AddMultiTenancy(options => options.Tenants.Add(Acme));
        services.Replace(ServiceDescriptor.Singleton<IEntityStorage, DistributedCacheStorage>());
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains($"{nameof(IEntityStorage)} is not kept per tenant", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A budget of an enabled endpoint is checked as well, named with its key.
    /// </summary>
    [Fact]
    public void AnEndpointBudgetReplacedAfterMultiTenancy_IsRefusedAtStartup()
    {
        var services = new ServiceCollection().AddServerStorage().AddIntrospection();
        services.AddMultiTenancy(options => options.Tenants.Add(Acme));
        services.AddKeyedSingleton(
            CallerRateLimiters.Introspection,
            PartitionedRateLimiter.Create<(string ClientId, string? Source), string>(
                resource => RateLimitPartition.GetNoLimiter(resource.ClientId)));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains(CallerRateLimiters.Introspection, refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheStorageTheServerResolves_IsKeptPerTenant()
    {
        using var provider = BuildProvider();

        Assert.IsType<TenantEntityStorage>(provider.GetRequiredService<IEntityStorage>());
    }

    /// <summary>
    /// A request that reached the server without a tenant has no issuer of its own; answering with the host
    /// would mint tokens every tenant on it accepts.
    /// </summary>
    [Fact]
    public void WithoutATenant_TheIssuerIsRefused()
    {
        using var provider = BuildProvider();
        EnterTenant(provider, null);

        var issuerProvider = provider.GetRequiredService<IIssuerProvider>();

        var refusal = Assert.Throws<InvalidOperationException>(() => issuerProvider.GetIssuer());
        Assert.Contains("not resolved to a tenant", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AConfiguredIssuer_IsRefusedAtStartup()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>().Configure(options => options.Issuer = "https://auth.example.com");
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
        Assert.Contains(nameof(OidcOptions.Issuer), refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A setting a tenant declares, set for the whole server, is refused at startup. Which settings those are is
    /// held by the core's own tests of the refusal; this one holds that multi-tenancy puts the refusal in force.
    /// </summary>
    [Fact]
    public void ServerWideClients_AreRefusedAtStartup()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>().Configure(options => options.Clients = [new ClientInfo("client")]);
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
        Assert.Contains($"{nameof(OidcOptions)}.{nameof(OidcOptions.Clients)} ", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UnderATenant_TheClientsAreTheOnesItDeclares()
    {
        var acme = new TenantDefinition { Id = "acme", Issuer = AcmeIssuer, Clients = [new ClientInfo("client")] };
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(acme));
        using var provider = services.BuildServiceProvider();
        EnterTenant(provider, acme);

        Assert.Same(acme.Clients, provider.GetRequiredService<IIssuerSettings>().Clients);
    }

    [Fact]
    public void EachTenant_KeepsAValueOfItsOwn_AndNoTenantGetsNone()
    {
        using var provider = BuildProvider();
        var local = provider.GetRequiredService<IIssuerLocal<object>>();
        var globex = new TenantDefinition { Id = "globex", Issuer = "https://auth.example.com/tenants/globex" };

        EnterTenant(provider, Acme);
        var acmeValue = local.GetOrCreate(null, () => new object());
        Assert.Same(acmeValue, local.GetOrCreate(null, () => new object()));

        EnterTenant(provider, globex);
        Assert.NotSame(acmeValue, local.GetOrCreate(null, () => new object()));

        EnterTenant(provider, null);
        var refusal = Assert.Throws<InvalidOperationException>(() => local.GetOrCreate(null, () => new object()));
        Assert.Contains("outside any tenant", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A tenant created again under the id of one removed builds its own values, rather than taking over what was
    /// built for the removed one.
    /// </summary>
    [Fact]
    public void ATenantCreatedAgainUnderAnId_BuildsValuesOfItsOwn()
    {
        using var provider = BuildProvider();
        var local = provider.GetRequiredService<IIssuerLocal<object>>();
        TenantDefinition Acme(string generation)
            => new() { Id = "acme", Issuer = AcmeIssuer, Generation = generation };

        EnterTenant(provider, Acme("1"));
        var former = local.GetOrCreate(null, () => new object());

        EnterTenant(provider, Acme("2"));
        Assert.NotSame(former, local.GetOrCreate(null, () => new object()));
    }

    /// <summary>
    /// The keys the server mints for a tenant are kept in a partition named by its id and generation, so a tenant
    /// created again under the id of one removed mints keys of its own; a tenant the settings declare keeps the
    /// partition named by its id alone.
    /// </summary>
    [Fact]
    public void TheKeyRing_KeepsAPartitionForEachCreationOfATenant()
    {
        using var provider = MintingKeys(
            Acme,
            new TenantDefinition { Id = "globex", Issuer = "https://auth.example.com/tenants/globex", Generation = "2" });

        Assert.Equal(["acme", "globex~2"], provider.GetRequiredService<IOptions<KeyRingOptions>>().Value.Partitions);
    }

    /// <summary>
    /// A generation names the tenant's data and keys, so one holding what a store may refuse is refused at startup.
    /// </summary>
    [Fact]
    public void AGenerationHoldingWhatAStoreMayRefuse_IsRefusedAtStartup()
    {
        using var provider = KeysFromSettings(new TenantDefinition
        {
            Id = "acme",
            Issuer = AcmeIssuer,
            Generation = "a.b",
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
        });

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains("The generation 'a.b' of tenant 'acme'", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void WithoutATenant_TheSettingsAreRefused()
    {
        using var provider = BuildProvider();
        EnterTenant(provider, null);

        var settings = provider.GetRequiredService<IIssuerSettings>();

        var refusal = Assert.Throws<InvalidOperationException>(() => settings.Clients);
        Assert.Contains("outside any tenant", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheCatalog_FindsATenantByIdExactly_AndByItsIssuersAddress()
    {
        var services = new ServiceCollection();
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        await using var provider = services.BuildServiceProvider();
        var catalog = provider.GetRequiredService<ITenantCatalog>();
        var cancellationToken = TestContext.Current.CancellationToken;

        Assert.Equal("acme", (await catalog.FindByIdAsync("acme", cancellationToken))?.Id);
        Assert.Null(await catalog.FindByIdAsync("ACME", cancellationToken));
        Assert.Equal("acme",
            (await catalog.FindByAddressAsync("AUTH.example.com.", "/tenants/acme/connect/token", cancellationToken))?.Id);
        Assert.Null(await catalog.FindByAddressAsync("auth.example.com", "/connect/token", cancellationToken));
    }

    /// <summary>
    /// Resolution missing from the pipeline looks exactly like a request naming no tenant, so the refusal is
    /// logged only in the first case: every OpenID endpoint answers 404 there, and the log names the missing call.
    /// </summary>
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task ARefusalWithoutResolution_IsLogged_AndOneAfterIt_IsNot(bool resolutionRan, bool logged)
    {
        var logs = new EventRecorder();
        var services = new ServiceCollection();
        services.AddSingleton<ILoggerFactory>(logs);
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        await using var provider = services.BuildServiceProvider();

        var context = new DefaultHttpContext { RequestServices = provider };
        context.Request.Host = new HostString("other.example.com");
        provider.GetRequiredService<IHttpContextAccessor>().HttpContext = context;

        var unmet = false;
        RequestDelegate endpoint = httpContext =>
        {
            unmet = TenantRequirement.IsUnmet(httpContext);
            return Task.CompletedTask;
        };

        if (resolutionRan)
            await new TenantResolutionMiddleware(endpoint, provider.GetRequiredService<ITenantCatalog>()).InvokeAsync(context);
        else
            await endpoint(context);

        Assert.True(unmet);
        Assert.Equal(logged, logs.EventIds.Contains(LogEvents.MultiTenancy.ResolutionNotInPipeline));
    }

    private sealed class EventRecorder : ILoggerFactory, ILogger
    {
        public List<int> EventIds { get; } = [];

        public ILogger CreateLogger(string categoryName) => this;

        public void AddProvider(ILoggerProvider provider)
        {
        }

        public void Dispose()
        {
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
            => EventIds.Add(eventId.Id);
    }

    /// <summary>
    /// A request that names no tenant is refused at the OpenID endpoints only where multi-tenancy is on; a
    /// deployment that never enabled it serves as before.
    /// </summary>
    [Fact]
    public void TheTenantRequirement_HoldsOnlyUnderMultiTenancy()
    {
        using var plain = new ServiceCollection().BuildServiceProvider();
        using var multiTenant = BuildProvider();

        Assert.False(TenantRequirement.IsUnmet(new DefaultHttpContext { RequestServices = plain }));

        EnterTenant(multiTenant, null);
        Assert.True(TenantRequirement.IsUnmet(new DefaultHttpContext { RequestServices = multiTenant }));

        EnterTenant(multiTenant, Acme);
        Assert.False(TenantRequirement.IsUnmet(new DefaultHttpContext { RequestServices = multiTenant }));
    }

    /// <summary>
    /// The tenant is asked of the accessor everywhere, so a host that resolves tenants its own way - setting
    /// nothing on the request - is answered the same by the endpoints as by the issuer.
    /// </summary>
    [Fact]
    public void AHostsOwnTenantAccessor_IsWhatEveryQuestionAsks()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ITenantAccessor>(new FixedTenantAccessor(Acme));
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        var context = new DefaultHttpContext { RequestServices = provider };

        Assert.False(TenantRequirement.IsUnmet(context));
        Assert.Same(Acme, TenantRequirement.CurrentTenant(context)?.Tenant);
        Assert.Equal(AcmeIssuer, provider.GetRequiredService<IIssuerProvider>().GetIssuer());
    }

    private sealed class FixedTenantAccessor(TenantDefinition tenant) : ITenantAccessor
    {
        public TenantContext Current { get; } = new() { Tenant = tenant };
    }
}
