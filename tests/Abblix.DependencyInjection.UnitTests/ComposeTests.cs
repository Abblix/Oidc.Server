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

using System;
using Abblix.DependencyInjection.UnitTests.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace Abblix.DependencyInjection.UnitTests;

/// <summary>
/// Locks the composition contract of <see cref="ServiceCollectionExtensions.Compose{TInterface,TComposite}"/>:
/// a family is composed once, and a second composition of the same composite is rejected loudly instead of
/// building a self-referential composite that deadlocks on first resolve (the double-opt-in defect).
/// </summary>
public class ComposeTests
{
    [Fact]
    public void Compose_CoversAFamilyOfOne()
    {
        var services = new ServiceCollection();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPrimaryService, ServiceA>());

        services.Compose<IPrimaryService, PrimaryServiceComposite>();

        // Skipping a family of one leaves the caller believing in a composite that is not there, and every
        // later decision - the guard against a second composition, the cursor's choice of path, the routing
        // the composite performs - reads that state differently from the caller.
        using var provider = services.BuildServiceProvider();
        var resolved = provider.GetRequiredService<IPrimaryService>();

        Assert.IsType<PrimaryServiceComposite>(resolved);
        Assert.StartsWith(nameof(ServiceA), resolved.GetValue());
    }

    [Fact]
    public void Compose_LeavesAFamilyOfNoneAlone()
    {
        var services = new ServiceCollection();

        services.Compose<IPrimaryService, PrimaryServiceComposite>();

        // Nothing to compose, and registering a composite over nothing would make the service resolvable
        // where the host registered none.
        Assert.Empty(services);
    }

    /// <summary>
    /// The happy path stays intact: composing a family once yields a single composite that wraps every leaf.
    /// </summary>
    [Fact]
    public void Compose_Once_WrapsAllLeavesInComposite()
    {
        var services = new ServiceCollection();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPrimaryService, ServiceA>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPrimaryService, ServiceB>());

        services.Compose<IPrimaryService, PrimaryServiceComposite>();

        using var provider = services.BuildServiceProvider();
        var resolved = provider.GetRequiredService<IPrimaryService>();

        Assert.IsType<PrimaryServiceComposite>(resolved);
        var value = resolved.GetValue();
        Assert.Contains("ServiceA", value);
        Assert.Contains("ServiceB", value);
    }

    /// <summary>
    /// The core regression. A second composition of the same composite (what a double opt-in produces once the
    /// first Compose has removed the leaves and the second call re-adds them) must throw at registration time
    /// rather than silently building a composite whose alias child resolves back to the composite under
    /// construction - a singleton that deadlocks forever on first resolve. Asserting the throw is safe because
    /// the collection is never resolved, so the latent deadlock is never reached.
    /// </summary>
    [Fact]
    public void Compose_SecondTimeForSameComposite_ThrowsInsteadOfSelfReferentialComposite()
    {
        var services = new ServiceCollection();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPrimaryService, ServiceA>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPrimaryService, ServiceB>());
        services.Compose<IPrimaryService, PrimaryServiceComposite>();

        // Re-add the leaves exactly as an accidental second opt-in would: the first Compose physically removed
        // the originals, so TryAddEnumerable no longer dedupes them and they land beside the alias.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPrimaryService, ServiceA>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPrimaryService, ServiceB>());

        var ex = Assert.Throws<InvalidOperationException>(
            () => services.Compose<IPrimaryService, PrimaryServiceComposite>());

        Assert.Contains(nameof(IPrimaryService), ex.Message);
    }

    [Fact]
    public void Compose_SecondTimeForADifferentComposite_ThrowsToo()
    {
        var services = new ServiceCollection();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPrimaryService, ServiceA>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPrimaryService, ServiceB>());
        services.Compose<IPrimaryService, PrimaryServiceComposite>();

        // The question is whether THIS FAMILY is composed, not whether that composite type is registered. Asked
        // the second way, this passes - and then the first composite's own alias, the one plain registration of
        // the interface left standing, becomes a member of the family it heads. The resolve never returns.
        var ex = Assert.Throws<InvalidOperationException>(
            () => services.Compose<IPrimaryService, SecondPrimaryServiceComposite>());

        Assert.Contains(nameof(IPrimaryService), ex.Message);
    }
}
