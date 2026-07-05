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
/// Locks the keyed live-cursor family API: several pipelines of one interface, each composed under its own key,
/// stay isolated (members keyed by a <see cref="ComposedFamilyKey"/> pairing the service key with the composite
/// type); DecomposeKeyed returns a live cursor whose edits reach the keyed composite at resolve; and the plain
/// and keyed families coexist.
/// </summary>
public class ComposeKeyedTests
{
    private const string EmailKey = "email";
    private const string SmsKey = "sms";

    private static ServiceCollection KeyedFamily(string serviceKey = EmailKey)
    {
        var services = new ServiceCollection();
        services.AddKeyedSingleton<IPipelineStep, StepA>(serviceKey);
        services.AddKeyedSingleton<IPipelineStep, StepB>(serviceKey);
        services.ComposeKeyed<IPipelineStep, PipelineComposite>(serviceKey);
        return services;
    }

    private static string ResolveKeyed(IServiceCollection services, string serviceKey)
    {
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredKeyedService<IPipelineStep>(serviceKey).Name;
    }

    private static ServiceDescriptor Step<TStep>() where TStep : class, IPipelineStep
        => ServiceDescriptor.Singleton<IPipelineStep, TStep>();

    [Fact]
    public void ComposeKeyed_FoldsTheFamilyUnderTheKey()
    {
        var services = KeyedFamily();

        using var provider = services.BuildServiceProvider();

        Assert.IsType<PipelineComposite>(provider.GetRequiredKeyedService<IPipelineStep>(EmailKey));
        Assert.Equal("A,B", provider.GetRequiredKeyedService<IPipelineStep>(EmailKey).Name);
        Assert.Null(provider.GetService<IPipelineStep>());
    }

    /// <summary>
    /// Two families of the same interface and composite class under different keys must not leak members into
    /// each other — the reason members are keyed by a (service key, composite type) pair.
    /// </summary>
    [Fact]
    public void ComposeKeyed_TwoFamiliesSameInterfaceAndComposite_StayIsolated()
    {
        var services = new ServiceCollection();
        services.AddKeyedSingleton<IPipelineStep, StepA>(EmailKey);
        services.AddKeyedSingleton<IPipelineStep, StepB>(EmailKey);
        services.AddKeyedSingleton<IPipelineStep, StepC>(SmsKey);
        services.AddKeyedSingleton<IPipelineStep, StepA>(SmsKey);
        services.ComposeKeyed<IPipelineStep, PipelineComposite>(EmailKey);
        services.ComposeKeyed<IPipelineStep, PipelineComposite>(SmsKey);

        Assert.Equal("A,B", ResolveKeyed(services, EmailKey));
        Assert.Equal("C,A", ResolveKeyed(services, SmsKey));
    }

    [Fact]
    public void ComposeKeyed_PlainFamilyOfSameInterface_Coexists()
    {
        var services = KeyedFamily();
        services.AddSingleton<IPipelineStep, StepC>();
        services.AddSingleton<IPipelineStep, StepA>();
        services.Compose<IPipelineStep, PipelineComposite>();

        using var provider = services.BuildServiceProvider();

        Assert.Equal("A,B", provider.GetRequiredKeyedService<IPipelineStep>(EmailKey).Name);
        Assert.Equal("C,A", provider.GetRequiredService<IPipelineStep>().Name);
    }

    [Fact]
    public void DecomposeKeyed_ExposesMembersInOrder()
    {
        var services = KeyedFamily();

        var composition = services.DecomposeKeyed<IPipelineStep>(EmailKey);

        Assert.Equal(
            [typeof(StepA), typeof(StepB)],
            composition.Select(member => member.ResolveImplementationType()).ToArray());
    }

    [Fact]
    public void DecomposeKeyed_WithoutPriorCompose_Throws()
    {
        var services = new ServiceCollection();
        services.AddKeyedSingleton<IPipelineStep, StepA>(EmailKey);

        var exception = Assert.Throws<InvalidOperationException>(
            () => services.DecomposeKeyed<IPipelineStep>(EmailKey));
        Assert.Contains(nameof(IPipelineStep), exception.Message);
        Assert.Contains(EmailKey, exception.Message);
    }

    [Fact]
    public void DecomposeKeyed_AddAfter_IsVisibleAtResolve_WithNoRecompose()
    {
        var services = KeyedFamily();

        services.DecomposeKeyed<IPipelineStep>(EmailKey).AddAfter<StepA>(Step<StepC>());

        Assert.Equal("A,C,B", ResolveKeyed(services, EmailKey));
    }

    [Fact]
    public void DecomposeKeyed_ChainedEdits_ApplyLive()
    {
        var services = KeyedFamily();

        services.DecomposeKeyed<IPipelineStep>(EmailKey)
            .Remove<StepB>()
            .AddFirst(Step<StepC>());

        Assert.Equal("C,A", ResolveKeyed(services, EmailKey));
    }

    [Fact]
    public void ComposeKeyed_SecondTimeForSameKey_Throws()
    {
        var services = KeyedFamily();
        services.AddKeyedSingleton<IPipelineStep, StepC>(EmailKey);

        var exception = Assert.Throws<InvalidOperationException>(
            () => services.ComposeKeyed<IPipelineStep, PipelineComposite>(EmailKey));
        Assert.Contains(nameof(PipelineComposite), exception.Message);
    }

    [Fact]
    public void ComposeKeyed_MixedMemberLifetimes_ComposesWithCompositeAtShortestLifetime()
    {
        var services = new ServiceCollection();
        services.AddKeyedSingleton<IPipelineStep, StepA>(EmailKey);
        services.AddKeyedScoped<IPipelineStep, StepB>(EmailKey);

        services.ComposeKeyed<IPipelineStep, PipelineComposite>(EmailKey);

        // The keyed composite adopts the shortest member lifetime (Scoped); the singleton member is shared.
        var composite = services.Single(descriptor =>
            descriptor is { IsKeyedService: true } &&
            descriptor.ServiceType == typeof(IPipelineStep) &&
            Equals(descriptor.ServiceKey, EmailKey));
        Assert.Equal(ServiceLifetime.Scoped, composite.Lifetime);

        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var scope = provider.CreateScope();
        Assert.Equal("A,B", scope.ServiceProvider.GetRequiredKeyedService<IPipelineStep>(EmailKey).Name);
    }

    [Fact]
    public void DecomposeKeyed_AfterEdit_ReflectsThePriorEdit()
    {
        var services = KeyedFamily();
        services.DecomposeKeyed<IPipelineStep>(EmailKey).AddLast(Step<StepC>());

        var reopened = services.DecomposeKeyed<IPipelineStep>(EmailKey);

        Assert.Equal(
            [typeof(StepA), typeof(StepB), typeof(StepC)],
            reopened.Select(member => member.ResolveImplementationType()).ToArray());
    }
}
