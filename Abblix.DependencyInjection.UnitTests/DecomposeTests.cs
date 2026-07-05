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
/// Locks the plain live-cursor family API: <see cref="ServiceCollectionExtensions.Compose{TInterface,TComposite}"/>
/// folds a family into one composite; <see cref="ServiceCollectionExtensions.Decompose{TInterface}"/> returns a
/// live <see cref="IComposition{TInterface}"/> cursor whose edits reach the composite at resolve with no recompose;
/// and <see cref="CompositionExtensions"/> adds position-aware sugar. Mixed member lifetimes fail loudly.
/// </summary>
public class DecomposeTests
{
    private static ServiceCollection ComposedFamily()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();
        services.AddSingleton<IPipelineStep, StepB>();
        services.Compose<IPipelineStep, PipelineComposite>();
        return services;
    }

    private static string Resolve(IServiceCollection services)
    {
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IPipelineStep>().Name;
    }

    private static ServiceDescriptor Step<TStep>() where TStep : class, IPipelineStep
        => ServiceDescriptor.Singleton<IPipelineStep, TStep>();

    [Fact]
    public void Compose_FoldsTheFamilyIntoOneComposite()
    {
        var services = ComposedFamily();

        using var provider = services.BuildServiceProvider();

        Assert.IsType<PipelineComposite>(provider.GetRequiredService<IPipelineStep>());
        Assert.Equal("A,B", provider.GetRequiredService<IPipelineStep>().Name);
    }

    [Fact]
    public void Compose_HidesMembersFromPluralResolution()
    {
        var services = ComposedFamily();

        using var provider = services.BuildServiceProvider();

        // Plural resolution yields a single element — the composite; members are keyed, invisible to plain resolve.
        Assert.Single(provider.GetServices<IPipelineStep>());
    }

    [Fact]
    public void Decompose_WithoutPriorCompose_Throws()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();

        var exception = Assert.Throws<InvalidOperationException>(() => services.Decompose<IPipelineStep>());
        Assert.Contains(nameof(IPipelineStep), exception.Message);
    }

    [Fact]
    public void Decompose_ExposesMembersInExecutionOrder()
    {
        var services = ComposedFamily();

        var composition = services.Decompose<IPipelineStep>();

        Assert.Equal(
            [typeof(StepA), typeof(StepB)],
            composition.Select(member => member.ResolveImplementationType()).ToArray());
    }

    [Fact]
    public void AddLast_IsVisibleAtResolve_WithNoRecompose()
    {
        var services = ComposedFamily();

        services.Decompose<IPipelineStep>().AddLast(Step<StepC>());

        Assert.Equal("A,B,C", Resolve(services));
    }

    [Fact]
    public void AddFirst_PrependsTheStep()
    {
        var services = ComposedFamily();

        services.Decompose<IPipelineStep>().AddFirst(Step<StepC>());

        Assert.Equal("C,A,B", Resolve(services));
    }

    [Fact]
    public void AddAfter_InsertsRightAfterTheAnchor()
    {
        var services = ComposedFamily();

        services.Decompose<IPipelineStep>().AddAfter<StepA>(Step<StepC>());

        Assert.Equal("A,C,B", Resolve(services));
    }

    [Fact]
    public void AddBefore_InsertsRightBeforeTheAnchor()
    {
        var services = ComposedFamily();

        services.Decompose<IPipelineStep>().AddBefore<StepB>(Step<StepC>());

        Assert.Equal("A,C,B", Resolve(services));
    }

    [Fact]
    public void Remove_DropsTheMember()
    {
        var services = ComposedFamily();

        services.Decompose<IPipelineStep>().Remove<StepA>();

        Assert.Equal("B", Resolve(services));
    }

    [Fact]
    public void Replace_SwapsTheMemberKeepingPosition()
    {
        var services = ComposedFamily();

        services.Decompose<IPipelineStep>().Replace<StepA>(Step<StepC>());

        Assert.Equal("C,B", Resolve(services));
    }

    [Fact]
    public void Edits_Chain_OnTheSameCursor()
    {
        var services = ComposedFamily();

        services.Decompose<IPipelineStep>()
            .AddFirst(Step<StepC>())
            .AddAfter<StepA>(Step<StepC>());

        Assert.Equal("C,A,C,B", Resolve(services));
    }

    [Fact]
    public void AddAfter_UnknownAnchor_Throws()
    {
        var services = ComposedFamily();

        var exception = Assert.Throws<InvalidOperationException>(
            () => services.Decompose<IPipelineStep>().AddAfter<StepC>(Step<StepC>()));
        Assert.Contains(nameof(StepC), exception.Message);
    }

    [Fact]
    public void Recompose_AppliesEditsInOneCall()
    {
        var services = ComposedFamily();

        services.Recompose<IPipelineStep>(composition =>
            composition.AddAfter<StepA>(Step<StepC>()));

        Assert.Equal("A,C,B", Resolve(services));
    }

    [Fact]
    public void Decompose_AfterEdit_ReflectsThePriorEdit()
    {
        var services = ComposedFamily();
        services.Decompose<IPipelineStep>().AddLast(Step<StepC>());

        var reopened = services.Decompose<IPipelineStep>();

        Assert.Equal(
            [typeof(StepA), typeof(StepB), typeof(StepC)],
            reopened.Select(member => member.ResolveImplementationType()).ToArray());
    }

    [Fact]
    public void Compose_MixedMemberLifetimes_Throws()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();
        services.AddScoped<IPipelineStep, StepB>();

        var exception = Assert.Throws<InvalidOperationException>(
            () => services.Compose<IPipelineStep, PipelineComposite>());
        Assert.Contains(nameof(IPipelineStep), exception.Message);
    }

    [Fact]
    public void AddingAMemberOfADifferentLifetime_Throws()
    {
        var services = ComposedFamily(); // composed as Singleton

        var exception = Assert.Throws<InvalidOperationException>(
            () => services.Decompose<IPipelineStep>()
                .AddLast(ServiceDescriptor.Scoped<IPipelineStep, StepC>()));
        Assert.Contains(nameof(IPipelineStep), exception.Message);
    }

    [Fact]
    public void Compose_SecondTimeForSameFamily_Throws()
    {
        var services = ComposedFamily();
        services.AddSingleton<IPipelineStep, StepC>();

        var exception = Assert.Throws<InvalidOperationException>(
            () => services.Compose<IPipelineStep, PipelineComposite>());
        Assert.Contains(nameof(PipelineComposite), exception.Message);
    }
}
