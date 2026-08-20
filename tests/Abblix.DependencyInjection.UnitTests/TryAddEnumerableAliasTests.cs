// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Linq;
using Abblix.DependencyInjection.UnitTests.Model;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.DependencyInjection.UnitTests;

/// <summary>
/// Locks the contract of <see cref="ServiceCollectionExtensions.TryAddEnumerableAlias{TService,TImplementation}"/>:
/// shared-instance enumerable aliases that respect the source registration's lifetime,
/// dedupe on repeated calls, and route through the source for every resolution path.
/// Sister suite to <see cref="AddAliasTests"/> covering the enumerable-strategy variant.
/// </summary>
public class TryAddEnumerableAliasTests
{
    /// <summary>
    /// The core invariant the helper exists to enforce: resolving the alias service goes
    /// through the source registration, so the alias and the source share one instance.
    /// </summary>
    [Fact]
    public void TryAddEnumerableAlias_SharesInstanceBetweenSourceAndAlias()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ServiceA>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();

        var provider = services.BuildServiceProvider();

        var concrete = provider.GetRequiredService<ServiceA>();
        var aliased = provider.GetServices<IPrimaryService>().Single();

        Assert.Same(concrete, aliased);
    }

    /// <summary>
    /// Two aliases pointing at the same concrete source must both resolve to that single
    /// instance - the helper composes cleanly when a type implements multiple interfaces
    /// and the host wants every interface to see the same object.
    /// </summary>
    [Fact]
    public void TryAddEnumerableAlias_SameSource_TwoAliases_AllResolveToSameInstance()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ServiceA>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();
        services.TryAddEnumerableAlias<IAliasService, ServiceA>();

        var provider = services.BuildServiceProvider();

        var concrete = provider.GetRequiredService<ServiceA>();
        var asPrimary = provider.GetServices<IPrimaryService>().Single();
        var asAlias = provider.GetServices<IAliasService>().Single();

        Assert.Same(concrete, asPrimary);
        Assert.Same(concrete, asAlias);
    }

    /// <summary>
    /// Distinct impl types each contribute one element to the enumerable; ordering follows
    /// registration order (the strategy-set semantic of <c>TryAddEnumerable</c>).
    /// </summary>
    [Fact]
    public void TryAddEnumerableAlias_TwoDistinctImpls_PopulatesEnumerableWithBoth()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ServiceA>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();
        services.AddSingleton<ServiceB>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceB>();

        var provider = services.BuildServiceProvider();
        var primaries = provider.GetServices<IPrimaryService>().ToArray();

        Assert.Equal(2, primaries.Length);
        Assert.IsType<ServiceA>(primaries[0]);
        Assert.IsType<ServiceB>(primaries[1]);
    }

    /// <summary>
    /// <c>TryAddEnumerable</c> dedupes on <c>(ServiceType, ImplementationType)</c>. The helper
    /// uses a typed factory <c>Func&lt;IServiceProvider, TImpl&gt;</c> so each repeat call
    /// produces a descriptor with the same <c>ImplementationType</c>, and the second call
    /// is skipped - repeated invocations are idempotent.
    /// </summary>
    [Fact]
    public void TryAddEnumerableAlias_CalledTwiceForSameImpl_RegisteredOnce()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ServiceA>();

        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();

        var provider = services.BuildServiceProvider();
        var primaries = provider.GetServices<IPrimaryService>().ToArray();

        Assert.Single(primaries);
    }

    /// <summary>
    /// Dedup MUST happen at the <c>ServiceCollection</c> level, not just at resolve time.
    /// After two helper calls with the same <typeparamref>TImpl</typeparamref>, the
    /// descriptor list contains exactly one entry under <see cref="IPrimaryService"/>. This
    /// is the invariant the typed-factory shape (<c>Func&lt;IServiceProvider, TImpl&gt;</c>)
    /// preserves: a more compact untyped <c>ServiceDescriptor.Describe</c> form would bake
    /// the factory as <c>Func&lt;IServiceProvider, object&gt;</c>, making
    /// <c>GetImplementationType()</c> return <c>typeof(object)</c> - which makes
    /// <c>TryAddEnumerable</c> throw, not dedupe.
    /// </summary>
    [Fact]
    public void TryAddEnumerableAlias_TwoCalls_AddSingleDescriptorEntry()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ServiceA>();

        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();

        var primaryDescriptors = services
            .Where(d => d.ServiceType == typeof(IPrimaryService))
            .ToArray();

        Assert.Single(primaryDescriptors);
    }

    /// <summary>
    /// The dedup key is <c>(ServiceType, ImplementationType)</c> - different impls under
    /// the same TService coexist in the enumerable, but each appears once. Locks against
    /// regression where dedup might collapse to «ServiceType only» (which would silently
    /// drop the second contributor) or expand to «delegate identity» (which would add
    /// duplicates because each helper call creates a new closure).
    /// </summary>
    [Fact]
    public void TryAddEnumerableAlias_TwoImplsEachCalledTwice_TwoDistinctDescriptors()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ServiceA>();
        services.AddSingleton<ServiceB>();

        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceB>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceB>();

        var primaryDescriptors = services
            .Where(d => d.ServiceType == typeof(IPrimaryService))
            .ToArray();

        Assert.Equal(2, primaryDescriptors.Length);

        var provider = services.BuildServiceProvider();
        var primaries = provider.GetServices<IPrimaryService>().ToArray();
        Assert.Equal(2, primaries.Length);
        Assert.IsType<ServiceA>(primaries[0]);
        Assert.IsType<ServiceB>(primaries[1]);
    }

    /// <summary>
    /// Each helper call creates its own closure capturing <c>sourceServiceType</c>. If dedup
    /// were keyed off delegate identity (which it is NOT - TryAddEnumerable uses
    /// implementation type), distinct closures across calls would defeat dedup. This test
    /// pins the typed-factory shape: even though closures are distinct objects, the
    /// generic-arg-1 of <c>Func&lt;IServiceProvider, TImpl&gt;</c> is identical across
    /// calls, so <c>GetImplementationType()</c> returns the same TImpl and dedup fires.
    /// </summary>
    [Fact]
    public void TryAddEnumerableAlias_DistinctClosuresPerCall_StillDedupedByImplType()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ServiceA>();

        // Three calls - three distinct lambda closures captured inside the helper.
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();

        var primaryDescriptors = services
            .Where(d => d.ServiceType == typeof(IPrimaryService))
            .ToArray();

        Assert.Single(primaryDescriptors);
    }

    /// <summary>
    /// Lifetime is inherited from the source registration. A Singleton source keeps a single
    /// instance across every alias resolution, no matter how many scopes the host opens.
    /// </summary>
    [Fact]
    public void TryAddEnumerableAlias_SingletonSource_SameInstanceAcrossScopes()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ServiceA>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();

        var provider = services.BuildServiceProvider();
        using var scope1 = provider.CreateScope();
        using var scope2 = provider.CreateScope();

        var s1 = scope1.ServiceProvider.GetServices<IPrimaryService>().Single();
        var s2 = scope2.ServiceProvider.GetServices<IPrimaryService>().Single();

        Assert.Same(s1, s2);
    }

    /// <summary>
    /// A Scoped source produces one instance per scope: same scope → same alias instance,
    /// different scopes → different alias instances. Mirrors the source's lifetime exactly.
    /// </summary>
    [Fact]
    public void TryAddEnumerableAlias_ScopedSource_SameInstanceWithinScope_DifferentAcrossScopes()
    {
        var services = new ServiceCollection();
        services.AddScoped<ServiceA>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();

        var provider = services.BuildServiceProvider();
        using var scope1 = provider.CreateScope();
        using var scope2 = provider.CreateScope();

        var s1a = scope1.ServiceProvider.GetServices<IPrimaryService>().Single();
        var s1b = scope1.ServiceProvider.GetRequiredService<ServiceA>();
        var s2 = scope2.ServiceProvider.GetServices<IPrimaryService>().Single();

        Assert.Same(s1a, s1b);
        Assert.NotSame(s1a, s2);
    }

    /// <summary>
    /// A Transient source produces a fresh instance for every resolution - the «shared»
    /// invariant degenerates to «routed through source» since Transient gives a new instance
    /// each call. The alias still goes through the source factory, so behaviour is consistent
    /// with a direct Transient resolution.
    /// </summary>
    [Fact]
    public void TryAddEnumerableAlias_TransientSource_FreshInstancePerResolution()
    {
        var services = new ServiceCollection();
        services.AddTransient<ServiceA>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();

        var provider = services.BuildServiceProvider();

        var first = provider.GetServices<IPrimaryService>().Single();
        var second = provider.GetServices<IPrimaryService>().Single();

        Assert.IsType<ServiceA>(first);
        Assert.IsType<ServiceA>(second);
        Assert.NotSame(first, second);
    }

    /// <summary>
    /// Calling the helper before the source is registered is a configuration mistake; the
    /// helper fails fast with a clear message rather than silently registering a broken
    /// alias the host will only discover at first resolution.
    /// </summary>
    [Fact]
    public void TryAddEnumerableAlias_NoSourceRegistration_Throws()
    {
        var services = new ServiceCollection();

        var ex = Assert.Throws<InvalidOperationException>(
            () => services.TryAddEnumerableAlias<IPrimaryService, ServiceA>());

        Assert.Contains(nameof(ServiceA), ex.Message);
    }

    /// <summary>
    /// The helper finds the source by either <c>ServiceType == TImpl</c> (concrete
    /// registration) or <c>ImplementationType == TImpl</c> (interface registration with TImpl
    /// behind it). Verifies the second case: source registered as another interface, alias
    /// still routes through the same instance.
    /// </summary>
    [Fact]
    public void TryAddEnumerableAlias_FindsSourceByImplementationType_NotJustServiceType()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IBaseService, ServiceA>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();

        var provider = services.BuildServiceProvider();

        var asBase = provider.GetRequiredService<IBaseService>();
        var asPrimary = provider.GetServices<IPrimaryService>().Single();

        Assert.Same(asBase, asPrimary);
    }


    /// <summary>
    /// The helper uses <c>LastOrDefault</c> on the lookup, so when the same impl is
    /// registered multiple times, the most recent registration's lifetime wins. Locks
    /// against accidental drift if a host re-registers the same type with a different
    /// lifetime - alias follows whichever wins on resolve.
    /// </summary>
    [Fact]
    public void TryAddEnumerableAlias_PreservesSourceLifetime_NotHardcodedSingleton()
    {
        var services = new ServiceCollection();
        services.AddScoped<ServiceA>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();

        var aliasDescriptor = services.Single(d =>
            d.ServiceType == typeof(IPrimaryService) &&
            d.GetImplementationTypeOrDefault() == typeof(ServiceA));

        Assert.Equal(ServiceLifetime.Scoped, aliasDescriptor.Lifetime);
    }

    /// <summary>
    /// Combining the singular <see cref="ServiceCollectionExtensions.AddAlias{TService,TImplementation}"/>
    /// with the enumerable helper on the same source: a host can publish the source under
    /// one «primary» interface (singular resolve) and contribute it to a strategy-set under
    /// another (enumerable resolve), with all three resolutions returning the same instance.
    /// </summary>
    [Fact]
    public void TryAddEnumerableAlias_ComposesWithAddAlias_AllShareSameInstance()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ServiceA>();
        services.AddAlias<IBaseService, ServiceA>();
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();

        var provider = services.BuildServiceProvider();

        var concrete = provider.GetRequiredService<ServiceA>();
        var asBase = provider.GetRequiredService<IBaseService>();
        var asPrimary = provider.GetServices<IPrimaryService>().Single();

        Assert.Same(concrete, asBase);
        Assert.Same(concrete, asPrimary);
    }

    /// <summary>
    /// When the same <typeparamref>TImpl</typeparamref> is aliased to TWO different services,
    /// the second alias call must still resolve through the original concrete registration -
    /// NOT through the alias the first call just added. Otherwise the second alias's factory
    /// captures <c>sourceServiceType=TFirstAliasInterface</c>, and any later
    /// <c>Compose&lt;TFirstAliasInterface, TComposite&gt;()</c> swaps that resolution to
    /// <c>TComposite</c> - making the second alias's factory cast a composite to
    /// <c>TImpl</c> and throw <see cref="System.InvalidCastException"/>. This is the failure
    /// mode the «concrete-ServiceType wins over alias-ImplementationType» priority closes.
    /// </summary>
    [Fact]
    public void TryAddEnumerableAlias_PreferConcreteSource_OverPreviousAlias()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ServiceA>();

        // First call: ServiceA aliased under IPrimaryService.
        services.TryAddEnumerableAlias<IPrimaryService, ServiceA>();
        // Second call: ServiceA aliased under IAliasService. The lookup must still pick the
        // concrete ServiceA registration as «source», not the IPrimaryService alias added
        // immediately above (which has ImplementationType=ServiceA via factory generic-arg).
        services.TryAddEnumerableAlias<IAliasService, ServiceA>();

        // Mimic Compose<>'s effect on IPrimaryService: drop the existing alias-derived
        // registration, replace with one that resolves to a different type. If the second
        // alias had captured sourceServiceType=IPrimaryService, it would now cast that
        // composite to ServiceA and throw InvalidCastException at resolve time.
        var primaryDescriptors = services.Where(d => d.ServiceType == typeof(IPrimaryService)).ToArray();
        foreach (var d in primaryDescriptors)
            services.Remove(d);
        services.AddSingleton<IPrimaryService>(_ => new CompositeStandIn());

        var provider = services.BuildServiceProvider();

        var asAlias = provider.GetServices<IAliasService>().Single();
        Assert.IsType<ServiceA>(asAlias);
    }

    private sealed class CompositeStandIn : IPrimaryService
    {
        public string GetValue() => "composite";
    }
}