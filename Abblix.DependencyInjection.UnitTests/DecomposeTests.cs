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
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace Abblix.DependencyInjection.UnitTests;

internal interface IPipelineStep
{
    string Name { get; }
}

internal sealed class StepA : IPipelineStep { public string Name => "A"; }
internal sealed class StepB : IPipelineStep { public string Name => "B"; }
internal sealed class StepC : IPipelineStep { public string Name => "C"; }

/// <summary>
/// Composite over <see cref="IPipelineStep"/> that reports its children in execution order,
/// so tests can assert the exact family composition after Decompose/Compose round-trips.
/// </summary>
internal sealed class PipelineComposite : IPipelineStep
{
    public PipelineComposite(IPipelineStep[] steps) => Steps = steps;
    public IPipelineStep[] Steps { get; }
    public string Name => string.Join(",", Steps.Select(step => step.Name));
}

/// <summary>
/// Locks the contract of the family recomposition API: Compose keeps the family as keyed descriptor data,
/// Decompose returns that data as an editable member list, and the single-generic Compose overload rebuilds the family from
/// the edited list without the host ever naming the composite type — insertion at any position, removal and reordering are plain list operations.
/// </summary>
public class DecomposeTests
{
    private static ServiceCollection NewComposedFamily()
    {
        var services = new ServiceCollection();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPipelineStep, StepA>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPipelineStep, StepB>());
        services.Compose<IPipelineStep, PipelineComposite>();
        return services;
    }

    private static string ResolveComposedName(IServiceCollection services, bool validateScopes = false)
    {
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = validateScopes,
        });
        using var scope = provider.CreateScope();
        return scope.ServiceProvider.GetRequiredService<IPipelineStep>().Name;
    }

    /// <summary>
    /// The structural contract of the keyed-family rework: composition moves the leaves into keyed
    /// registrations whose service key is the composite type — the descriptors themselves are the family
    /// registry — while the plain resolve still yields only the composite.
    /// </summary>
    [Fact]
    public void Compose_Once_KeepsLeavesAsKeyedFamilyData()
    {
        var services = NewComposedFamily();

        var keyedLeaves = services
            .Where(descriptor => descriptor is { IsKeyedService: true } &&
                                 descriptor.ServiceType == typeof(IPipelineStep) &&
                                 Equals(descriptor.ServiceKey, typeof(PipelineComposite)))
            .ToArray();
        Assert.Equal(2, keyedLeaves.Length);

        using var provider = services.BuildServiceProvider();
        var plainResolved = provider.GetServices<IPipelineStep>().ToArray();
        var single = Assert.Single(plainResolved);
        Assert.IsType<PipelineComposite>(single);
    }

    [Fact]
    public void Compose_Once_CompositeReceivesLeavesInRegistrationOrder()
    {
        var services = NewComposedFamily();

        Assert.Equal("A,B", ResolveComposedName(services));
    }

    [Fact]
    public void Decompose_ComposedFamily_ReturnsMembersInOrderAndStripsFamily()
    {
        var services = NewComposedFamily();

        var members = services.Decompose<IPipelineStep>();

        Assert.Equal(
            [typeof(StepA), typeof(StepB)],
            members.Select(member => member.ResolveImplementationType()).ToArray());

        Assert.DoesNotContain(services, descriptor => descriptor.ServiceType == typeof(IPipelineStep));
        Assert.DoesNotContain(services, descriptor => descriptor.ServiceType == typeof(PipelineComposite));

        using var provider = services.BuildServiceProvider();
        Assert.Null(provider.GetService<IPipelineStep>());
    }

    [Fact]
    public void Decompose_WithoutPriorCompose_Throws()
    {
        var services = new ServiceCollection();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPipelineStep, StepA>());

        var ex = Assert.Throws<InvalidOperationException>(
            () => services.Decompose<IPipelineStep>());

        Assert.Contains(nameof(IPipelineStep), ex.Message);
    }

    [Fact]
    public void Compose_WithEditedMembers_InsertsStepBetween()
    {
        var services = NewComposedFamily();

        var members = services.Decompose<IPipelineStep>();
        members.Insert(1, ServiceDescriptor.Singleton<IPipelineStep, StepC>());
        services.Compose<IPipelineStep>(members);

        Assert.Equal("A,C,B", ResolveComposedName(services));
    }

    [Fact]
    public void Compose_WithEditedMembers_RemovesStep()
    {
        var services = NewComposedFamily();

        var members = services.Decompose<IPipelineStep>();
        members.RemoveAll(member => member.ResolveImplementationType() == typeof(StepA));
        services.Compose<IPipelineStep>(members);

        Assert.Equal("B", ResolveComposedName(services));
    }

    [Fact]
    public void Compose_WithReorderedMembers_ReversesExecutionOrder()
    {
        var services = NewComposedFamily();

        var members = services.Decompose<IPipelineStep>();
        members.Reverse();
        services.Compose<IPipelineStep>(members);

        Assert.Equal("B,A", ResolveComposedName(services));
    }

    /// <summary>
    /// Reordering is not limited to wholesale reversal: an arbitrary single-member move lands exactly
    /// where the list says, and the new order survives a further decompose/compose cycle.
    /// </summary>
    [Fact]
    public void Recompose_MovingMemberToFront_ChangesExecutionOrder()
    {
        var services = new ServiceCollection();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPipelineStep, StepA>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPipelineStep, StepB>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPipelineStep, StepC>());
        services.Compose<IPipelineStep, PipelineComposite>();

        services.Recompose<IPipelineStep>(members =>
        {
            var last = members[^1];
            members.RemoveAt(members.Count - 1);
            members.Insert(0, last);
        });

        Assert.Equal("C,A,B", ResolveComposedName(services));

        var reopened = services.Decompose<IPipelineStep>();
        Assert.Equal(
            [typeof(StepC), typeof(StepA), typeof(StepB)],
            reopened.Select(member => member.ResolveImplementationType()).ToArray());
    }

    [Fact]
    public void Compose_WithEmptyMembers_Throws()
    {
        var services = NewComposedFamily();

        services.Decompose<IPipelineStep>();

        var ex = Assert.Throws<InvalidOperationException>(
            () => services.Compose<IPipelineStep>(Array.Empty<ServiceDescriptor>()));

        Assert.Contains(nameof(IPipelineStep), ex.Message);
    }

    /// <summary>
    /// The composite type travels in the service keys of the members returned by Decompose; a list built
    /// entirely of new plain descriptors carries no composite type and must fail loud instead of guessing.
    /// </summary>
    [Fact]
    public void Compose_WithOnlyNewMembers_ThrowsExplainingUnknownComposite()
    {
        var services = NewComposedFamily();
        services.Decompose<IPipelineStep>();

        var newcomers = new[] { ServiceDescriptor.Singleton<IPipelineStep, StepC>() };

        var ex = Assert.Throws<InvalidOperationException>(
            () => services.Compose<IPipelineStep>(newcomers));

        Assert.Contains(nameof(IPipelineStep), ex.Message);
        Assert.Contains(nameof(ServiceCollectionExtensions.Decompose), ex.Message);
    }

    /// <summary>
    /// Family members registered through typed-factory descriptors (the shape
    /// <see cref="ServiceCollectionExtensions.TryAddEnumerableAlias{TService,TImplementation}"/> produces,
    /// used by the authorization-grant family) must survive the round-trip: their implementation type stays
    /// derivable for list editing, and the alias keeps sharing the instance with the concrete registration.
    /// </summary>
    [Fact]
    public void Decompose_FactoryRegisteredMember_KeepsIdentityAcrossRecompose()
    {
        var services = new ServiceCollection();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPipelineStep, StepA>());
        services.TryAddSingleton<StepB>();
        services.TryAddEnumerableAlias<IPipelineStep, StepB>();
        services.Compose<IPipelineStep, PipelineComposite>();

        var members = services.Decompose<IPipelineStep>();
        var anchorIndex = members.FindIndex(member => member.ResolveImplementationType() == typeof(StepB));
        members.Insert(anchorIndex + 1, ServiceDescriptor.Singleton<IPipelineStep, StepC>());
        services.Compose<IPipelineStep>(members);

        using var provider = services.BuildServiceProvider();
        var composite = Assert.IsType<PipelineComposite>(provider.GetRequiredService<IPipelineStep>());

        Assert.Equal("A,B,C", composite.Name);
        Assert.Same(provider.GetRequiredService<StepB>(), composite.Steps[1]);
    }

    /// <summary>
    /// The composite takes the shortest lifetime among the members it is composed from, and the interface
    /// alias follows — a scoped member must not end up captured inside a singleton composite.
    /// </summary>
    [Fact]
    public void Compose_WithScopedMember_PromotesCompositeAndAliasToScoped()
    {
        var services = NewComposedFamily();

        var members = services.Decompose<IPipelineStep>();
        members.Add(ServiceDescriptor.Scoped<IPipelineStep, StepC>());
        services.Compose<IPipelineStep>(members);

        var compositeDescriptor = Assert.Single(
            services, descriptor => descriptor.ServiceType == typeof(PipelineComposite));
        Assert.Equal(ServiceLifetime.Scoped, compositeDescriptor.Lifetime);

        var aliasDescriptor = Assert.Single(
            services,
            descriptor => descriptor is { IsKeyedService: false } &&
                          descriptor.ServiceType == typeof(IPipelineStep));
        Assert.Equal(ServiceLifetime.Scoped, aliasDescriptor.Lifetime);

        Assert.Equal("A,B,C", ResolveComposedName(services, validateScopes: true));
    }

    /// <summary>
    /// Recompose is the one-call shorthand: decompose, hand the list to the action, compose it back
    /// into the same composite type.
    /// </summary>
    [Fact]
    public void Recompose_WithModifyAction_AppliesEditsInOneCall()
    {
        var services = NewComposedFamily();

        services.Recompose<IPipelineStep>(members =>
        {
            members.RemoveAll(member => member.ResolveImplementationType() == typeof(StepB));
            members.Insert(0, ServiceDescriptor.Singleton<IPipelineStep, StepC>());
        });

        Assert.Equal("C,A", ResolveComposedName(services));
    }

    /// <summary>
    /// The cycle is repeatable: a recomposed family can be decomposed again and reflects the earlier edits.
    /// </summary>
    [Fact]
    public void Decompose_AfterRecompose_ReturnsEditedFamily()
    {
        var services = NewComposedFamily();

        var members = services.Decompose<IPipelineStep>();
        members.RemoveAll(member => member.ResolveImplementationType() == typeof(StepB));
        members.Add(ServiceDescriptor.Singleton<IPipelineStep, StepC>());
        services.Compose<IPipelineStep>(members);

        var reopened = services.Decompose<IPipelineStep>();

        Assert.Equal(
            [typeof(StepA), typeof(StepC)],
            reopened.Select(member => member.ResolveImplementationType()).ToArray());
    }
}
