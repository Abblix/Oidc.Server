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

using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace Abblix.DependencyInjection.UnitTests;

/// <summary>
/// Locks <see cref="ServiceCollectionExtensions.TryAddToFamily{TService,TImplementation}"/>: a family member
/// lands exactly once and reaches the composite, whether the family is still loose or already composed.
/// </summary>
public class TryAddToFamilyTests
{
    private static ServiceCollection LooseFamily()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();
        services.AddSingleton<IPipelineStep, StepB>();
        return services;
    }

    private static ServiceCollection ComposedFamily()
    {
        var services = LooseFamily();
        services.Compose<IPipelineStep, PipelineComposite>();
        return services;
    }

    private static string Resolve(IServiceCollection services)
    {
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IPipelineStep>().Name;
    }

    [Fact]
    public void TryAddToFamily_AddsTheMemberToALooseFamily()
    {
        var services = LooseFamily();

        services.TryAddToFamily<IPipelineStep, StepC>(ServiceLifetime.Singleton);

        using var provider = services.BuildServiceProvider();
        Assert.Equal(["A", "B", "C"], provider.GetServices<IPipelineStep>().Select(step => step.Name));
    }

    [Fact]
    public void TryAddToFamily_AddsTheMemberOnlyOnce()
    {
        var services = LooseFamily();

        services.TryAddToFamily<IPipelineStep, StepC>(ServiceLifetime.Singleton);
        services.TryAddToFamily<IPipelineStep, StepC>(ServiceLifetime.Singleton);

        using var provider = services.BuildServiceProvider();
        Assert.Single(provider.GetServices<IPipelineStep>(), step => step.Name == "C");
    }

    [Fact]
    public void TryAddToFamily_ReachesTheCompositeWhenTheFamilyIsAlreadyComposed()
    {
        var services = ComposedFamily();

        services.TryAddToFamily<IPipelineStep, StepC>(ServiceLifetime.Singleton);

        // The member joined the family rather than landing beside it: the composite reports it as a child.
        Assert.Equal("A,B,C", Resolve(services));
    }

    [Fact]
    public void TryAddToFamily_LeavesAComposedFamilyAloneWhenTheMemberIsAlreadyInIt()
    {
        var services = ComposedFamily();

        services.TryAddToFamily<IPipelineStep, StepA>(ServiceLifetime.Singleton);

        Assert.Equal("A,B", Resolve(services));

        // Nothing was left beside the composite: the only plain registration is the composite itself.
        Assert.Single(
            services, descriptor => !descriptor.IsKeyedService && descriptor.ServiceType == typeof(IPipelineStep));
    }

    [Fact]
    public void TryAddToFamily_SkipsAnImplementationTheFamilyHoldsAsAnInstance()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep>(new StepA());

        services.TryAddToFamily<IPipelineStep, StepA>(ServiceLifetime.Singleton);

        using var provider = services.BuildServiceProvider();
        Assert.Single(provider.GetServices<IPipelineStep>());
    }

    [Fact]
    public void TryAddToFamily_IgnoresAKeyedRegistrationThatIsNotAComposition()
    {
        var services = LooseFamily();

        // Someone else's keyed registration under the same interface. It is not a family member, and it does
        // not make the family composed.
        services.AddKeyedSingleton<IPipelineStep, StepA>("dispatch");

        services.TryAddToFamily<IPipelineStep, StepC>(ServiceLifetime.Singleton);

        using var provider = services.BuildServiceProvider();
        Assert.Equal(["A", "B", "C"], provider.GetServices<IPipelineStep>().Select(step => step.Name));
    }

    [Fact]
    public void TryAddToFamily_LeavesAKeyedCompositionOfTheSameInterfaceAlone()
    {
        var services = new ServiceCollection();
        services.AddKeyedSingleton<IPipelineStep, StepA>("primary");
        services.ComposeKeyed<IPipelineStep, PipelineComposite>("primary");
        services.AddSingleton<IPipelineStep, StepB>();

        services.TryAddToFamily<IPipelineStep, StepC>(ServiceLifetime.Singleton);

        // The keyed family is a different family: the member joins the plain one.
        using var provider = services.BuildServiceProvider();
        Assert.Equal(["B", "C"], provider.GetServices<IPipelineStep>().Select(step => step.Name));
    }

    [Fact]
    public void TryAddToFamily_AddsAMemberTheFamilyLacksThoughAKeyedRegistrationNamesIt()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();

        // The same implementation registered under a key belongs to whoever asked for that key, not to
        // this family, so it is no reason to withhold the member.
        services.AddKeyedSingleton<IPipelineStep, StepC>("dispatch");

        services.TryAddToFamily<IPipelineStep, StepC>(ServiceLifetime.Singleton);

        using var provider = services.BuildServiceProvider();
        Assert.Equal(["A", "C"], provider.GetServices<IPipelineStep>().Select(step => step.Name));
    }

    [Fact]
    public void TryAddToFamily_SkipsAMemberAComposedFamilyHoldsAsAnInstance()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep>(new StepA());
        services.AddSingleton<IPipelineStep, StepB>();
        services.Compose<IPipelineStep, PipelineComposite>();

        // Composition preserves an instance member as a keyed instance, so only ResolveImplementationType
        // can tell that StepA is already in the family.
        services.TryAddToFamily<IPipelineStep, StepA>(ServiceLifetime.Singleton);

        Assert.Equal("A,B", Resolve(services));
    }

    [Fact]
    public void TryAddToFamily_HonoursTheRequestedLifetime()
    {
        var services = LooseFamily();

        services.TryAddToFamily<IPipelineStep, StepC>(ServiceLifetime.Scoped);

        var member = Assert.Single(services, descriptor => descriptor.ImplementationType == typeof(StepC));
        Assert.Equal(ServiceLifetime.Scoped, member.Lifetime);
    }

    [Fact]
    public void TryAddEnumerable_UnseatsTheCompositeItselfCannotSee()
    {
        var services = ComposedFamily();

        // The hazard this method exists to avoid. TryAddEnumerable deduplicates against plain descriptors,
        // and composition moved the members to keyed ones, so it adds a plain descriptor beside the
        // composite - which then wins the singular resolve, because last registration wins.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPipelineStep, StepC>());

        Assert.Equal("C", Resolve(services));
    }
}
