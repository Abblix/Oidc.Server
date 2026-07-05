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
using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.DependencyInjection.UnitTests;

/// <summary>
/// Locks the contract of the keyed family API: keyed registrations under a host-chosen service key compose
/// into a composite resolvable under that same key, member data is stored under a
/// <see cref="ComposedFamilyKey"/> pairing the service key with the composite type — so same-interface
/// families under different keys stay isolated — and DecomposeKeyed/ComposeKeyed/RecomposeKeyed mirror the
/// plain list-editing workflow.
/// </summary>
public class ComposeKeyedTests
{
    private static ServiceCollection NewKeyedFamily(string serviceKey = "email")
    {
        var services = new ServiceCollection();
        services.AddKeyedSingleton<IPipelineStep, StepA>(serviceKey);
        services.AddKeyedSingleton<IPipelineStep, StepB>(serviceKey);
        services.ComposeKeyed<IPipelineStep, PipelineComposite>(serviceKey);
        return services;
    }

    private static string ResolveKeyedName(IServiceCollection services, string serviceKey)
    {
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredKeyedService<IPipelineStep>(serviceKey).Name;
    }

    [Fact]
    public void ComposeKeyed_Once_ComposesMembersUnderTheServiceKey()
    {
        var services = NewKeyedFamily();

        using var provider = services.BuildServiceProvider();
        var composed = provider.GetRequiredKeyedService<IPipelineStep>("email");

        Assert.IsType<PipelineComposite>(composed);
        Assert.Equal("A,B", composed.Name);
        Assert.Null(provider.GetService<IPipelineStep>());
    }

    /// <summary>
    /// The reason members are keyed by a (service key, composite type) pair: two families of the same
    /// interface under different keys — even sharing the composite class — must not leak members into
    /// each other.
    /// </summary>
    [Fact]
    public void ComposeKeyed_TwoFamiliesSameInterfaceAndComposite_StayIsolated()
    {
        var services = new ServiceCollection();
        services.AddKeyedSingleton<IPipelineStep, StepA>("email");
        services.AddKeyedSingleton<IPipelineStep, StepB>("email");
        services.AddKeyedSingleton<IPipelineStep, StepC>("sms");
        services.AddKeyedSingleton<IPipelineStep, StepA>("sms");
        services.ComposeKeyed<IPipelineStep, PipelineComposite>("email");
        services.ComposeKeyed<IPipelineStep, PipelineComposite>("sms");

        Assert.Equal("A,B", ResolveKeyedName(services, "email"));
        Assert.Equal("C,A", ResolveKeyedName(services, "sms"));
    }

    [Fact]
    public void ComposeKeyed_PlainFamilyOfSameInterface_Coexists()
    {
        var services = NewKeyedFamily();
        services.AddSingleton<IPipelineStep, StepC>();
        services.AddSingleton<IPipelineStep, StepA>();
        services.Compose<IPipelineStep, PipelineComposite>();

        using var provider = services.BuildServiceProvider();

        Assert.Equal("A,B", provider.GetRequiredKeyedService<IPipelineStep>("email").Name);
        Assert.Equal("C,A", provider.GetRequiredService<IPipelineStep>().Name);
    }

    [Fact]
    public void DecomposeKeyed_ReturnsMembersInOrderAndStripsFamily()
    {
        var services = NewKeyedFamily();

        var members = services.DecomposeKeyed<IPipelineStep>("email");

        Assert.Equal(
            [typeof(StepA), typeof(StepB)],
            members.Select(member => member.ResolveImplementationType()).ToArray());

        Assert.DoesNotContain(services, descriptor => descriptor.ServiceType == typeof(IPipelineStep));

        using var provider = services.BuildServiceProvider();
        Assert.Null(provider.GetKeyedService<IPipelineStep>("email"));
    }

    [Fact]
    public void DecomposeKeyed_WithoutPriorCompose_Throws()
    {
        var services = new ServiceCollection();
        services.AddKeyedSingleton<IPipelineStep, StepA>("email");

        var ex = Assert.Throws<InvalidOperationException>(
            () => services.DecomposeKeyed<IPipelineStep>("email"));

        Assert.Contains(nameof(IPipelineStep), ex.Message);
        Assert.Contains("email", ex.Message);
    }

    [Fact]
    public void ComposeKeyed_WithEditedMembers_InsertsStepBetween()
    {
        var services = NewKeyedFamily();

        var members = services.DecomposeKeyed<IPipelineStep>("email");
        members.Insert(1, ServiceDescriptor.Singleton<IPipelineStep, StepC>());
        services.ComposeKeyed<IPipelineStep>("email", members);

        Assert.Equal("A,C,B", ResolveKeyedName(services, "email"));
    }

    [Fact]
    public void RecomposeKeyed_WithModifyAction_AppliesEditsInOneCall()
    {
        var services = NewKeyedFamily();

        services.RecomposeKeyed<IPipelineStep>("email", members =>
        {
            members.RemoveAll(member => member.ResolveImplementationType() == typeof(StepB));
            members.Insert(0, ServiceDescriptor.Singleton<IPipelineStep, StepC>());
        });

        Assert.Equal("C,A", ResolveKeyedName(services, "email"));
    }

    [Fact]
    public void ComposeKeyed_SecondTimeForSameKey_Throws()
    {
        var services = NewKeyedFamily();
        services.AddKeyedSingleton<IPipelineStep, StepC>("email");

        var ex = Assert.Throws<InvalidOperationException>(
            () => services.ComposeKeyed<IPipelineStep, PipelineComposite>("email"));

        Assert.Contains(nameof(PipelineComposite), ex.Message);
    }

    [Fact]
    public void ComposeKeyed_WithScopedMember_PromotesCompositeToScoped()
    {
        var services = NewKeyedFamily();

        var members = services.DecomposeKeyed<IPipelineStep>("email");
        members.Add(ServiceDescriptor.Scoped<IPipelineStep, StepC>());
        services.ComposeKeyed<IPipelineStep>("email", members);

        var compositeDescriptor = Assert.Single(
            services,
            descriptor => descriptor is { IsKeyedService: true } &&
                          descriptor.ServiceType == typeof(IPipelineStep) &&
                          Equals(descriptor.ServiceKey, "email"));
        Assert.Equal(ServiceLifetime.Scoped, compositeDescriptor.Lifetime);

        using var provider = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
        });
        using var scope = provider.CreateScope();
        Assert.Equal("A,B,C", scope.ServiceProvider.GetRequiredKeyedService<IPipelineStep>("email").Name);
    }

    /// <summary>
    /// The cycle is repeatable and the member keys are self-describing: a recomposed keyed family can be
    /// decomposed again and reflects the earlier edits.
    /// </summary>
    [Fact]
    public void DecomposeKeyed_AfterRecompose_ReturnsEditedFamily()
    {
        var services = NewKeyedFamily();

        services.RecomposeKeyed<IPipelineStep>("email", members =>
            members.Add(ServiceDescriptor.Singleton<IPipelineStep, StepC>()));

        var reopened = services.DecomposeKeyed<IPipelineStep>("email");

        Assert.Equal(
            [typeof(StepA), typeof(StepB), typeof(StepC)],
            reopened.Select(member => member.ResolveImplementationType()).ToArray());
    }
}
