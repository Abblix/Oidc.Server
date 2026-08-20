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

        // Plural resolution yields a single element - the composite; members are keyed, invisible to plain resolve.
        Assert.Single(provider.GetServices<IPipelineStep>());
    }

    [Fact]
    public void Decompose_WithoutPriorCompose_EditsThePlainMembers()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();

        // A family that has not been composed is still a family, and editing its members is the only reason to
        // ask for the cursor. Where the members live is the cursor's business, not the caller's.
        services.Decompose<IPipelineStep>().AddLast(Step<StepB>());

        using var provider = services.BuildServiceProvider();
        Assert.Equal(["A", "B"], provider.GetServices<IPipelineStep>().Select(step => step.Name));
    }

    [Fact]
    public void Decompose_OnAnUnregisteredFamily_StartsItEmpty()
    {
        var services = new ServiceCollection();

        var composition = services.Decompose<IPipelineStep>();

        Assert.Empty(composition);

        composition.AddLast(Step<StepA>());

        using var provider = services.BuildServiceProvider();
        Assert.Equal(["A"], provider.GetServices<IPipelineStep>().Select(step => step.Name));
    }

    [Fact]
    public void Decompose_OnAnEmptiedComposedFamily_StillKnowsItsComposite()
    {
        var services = ComposedFamily();

        services.Decompose<IPipelineStep>().Clear();

        // Nothing is left keyed, so the members no longer name the composite. Read from them, the family would
        // look as if it had never been composed, and the composite - a plain registration of the interface -
        // would be taken for a member of the family it heads.
        var composition = services.Decompose<IPipelineStep>();
        Assert.Empty(composition);

        composition.AddLast(Step<StepC>());

        Assert.Equal("C", Resolve(services));
        Assert.IsType<PipelineComposite>(services.BuildServiceProvider().GetRequiredService<IPipelineStep>());
    }

    [Fact]
    public void Decompose_RefusesAComposedFamilyWhoseCursorWasRemoved()
    {
        var services = ComposedFamily();

        // Nothing in this API removes it. Should anything ever manage to, the members are still there and still
        // keyed as members, so answering with a fresh cursor would read the family as never composed.
        // The entry a composition leaves is keyed and is the only registration in the collection whose service
        // type is neither the family interface nor the composite - its type is internal to the library.
        var entry = Assert.Single(
            services,
            descriptor => descriptor.IsKeyedService && descriptor.ServiceType != typeof(IPipelineStep));
        services.Remove(entry);

        var exception = Assert.Throws<InvalidOperationException>(() => services.Decompose<IPipelineStep>());
        Assert.Contains(nameof(IPipelineStep), exception.Message);
    }

    [Fact]
    public void Decompose_TellsComposedFamiliesApart()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();
        services.AddSingleton<IPipelineStep, StepB>();
        services.AddSingleton<IPrimaryService, ServiceA>();
        services.AddSingleton<IPrimaryService, ServiceB>();

        services.Compose<IPipelineStep, PipelineComposite>();
        services.Compose<IPrimaryService, PrimaryServiceComposite>();

        // Emptying one family is where a shared record would show: the other family's cursor would then read
        // the surviving record and take a composite that heads someone else's family.
        services.Decompose<IPipelineStep>().Clear();
        services.Decompose<IPipelineStep>().AddLast(Step<StepC>());

        // The other family's CURSOR is where a shared record shows: resolving it from the container never asks
        // which composite it has, so a collision would leave the container correct and the cursor blind.
        Assert.Equal(
            [typeof(ServiceA), typeof(ServiceB)],
            services.Decompose<IPrimaryService>().Select(member => member.ResolveImplementationType()).ToArray());

        using var provider = services.BuildServiceProvider();

        Assert.IsType<PipelineComposite>(provider.GetRequiredService<IPipelineStep>());
        Assert.Equal("C", provider.GetRequiredService<IPipelineStep>().Name);
        Assert.IsType<PrimaryServiceComposite>(provider.GetRequiredService<IPrimaryService>());
    }

    [Fact]
    public void ComposedFamilyMembers_AreInvisibleToTheUnkeyedLookups()
    {
        var services = ComposedFamily();

        // The members are keyed registrations of the same interface, so a lookup that counted them would find
        // several where the caller expects one and refuse to answer - which is what ChangeLifetime does.
        var descriptor = Assert.IsAssignableFrom<ServiceDescriptor>(services.Find<IPipelineStep>());
        Assert.Equal(typeof(PipelineComposite), descriptor.ResolveImplementationType());

        services.ChangeLifetime<IPipelineStep>(ServiceLifetime.Scoped);

        Assert.Equal("A,B", Resolve(services));
    }

    /// <summary>
    /// A canary, not a feature. The cursor needs the lifetime the composite was registered with, so that a
    /// member shorter-lived than the composite is refused instead of being captured by it. That lifetime is not
    /// stored anywhere: it is read back off the composite's own registration, which works only while
    /// <see cref="ServiceCollectionExtensions.Decorate{TInterface,TDecorator}"/> keeps replacing that
    /// registration in place with its lifetime intact.
    /// </summary>
    /// <remarks>
    /// If this goes red, the derivation underneath it is already wrong: a decorated family reports whatever
    /// lifetime the decorator was given, so the captive-member check silently starts judging against the wrong
    /// one. Do not adjust the assertion. Either restore decoration's lifetime, or stop deriving - put the
    /// lifetime back into <c>ComposedFamily</c>, which is where it lived before and costs one field.
    /// </remarks>
    [Fact]
    public void DecoratingAFamilyKeepsTheLifetimeItsMembersAreJudgedAgainst()
    {
        var services = new ServiceCollection();
        services.AddScoped<IPipelineStep, StepA>();
        services.AddScoped<IPipelineStep, StepB>();
        services.Compose<IPipelineStep, PipelineComposite>();

        services.Decorate<IPipelineStep, PipelineDecorator>();

        var composite = Assert.Single(
            services, descriptor => !descriptor.IsKeyedService && descriptor.ServiceType == typeof(IPipelineStep));
        Assert.Equal(ServiceLifetime.Scoped, composite.Lifetime);

        // And the derived lifetime still does its job: a Transient member would outlive nothing and be captured.
        var exception = Assert.Throws<InvalidOperationException>(
            () => services.Decompose<IPipelineStep>()
                .AddLast(ServiceDescriptor.Transient<IPipelineStep, StepC>()));

        Assert.Contains(nameof(ServiceLifetime.Scoped), exception.Message);
    }

    [Fact]
    public void Decompose_RefusesAFamilyWhoseCompositeWasRemoved()
    {
        var services = ComposedFamily();

        // RemoveAll takes the registrations an unkeyed resolve would reach, which for a composed family is the
        // composite alone. Answering with a cursor afterwards would accept members into a family nothing
        // resolves any more, and report success for a registration that can never take effect.
        services.RemoveAll<IPipelineStep>();

        var exception = Assert.Throws<InvalidOperationException>(() => services.Decompose<IPipelineStep>());

        // Named precisely, so this cannot pass on the sibling refusal for a family whose mark was removed.
        Assert.Contains("composite that heads it", exception.Message);
    }

    [Fact]
    public void ACopiedFamilyIsEditedInTheCollectionItWasCopiedInto()
    {
        var source = ComposedFamily();

        IServiceCollection target = new ServiceCollection();
        foreach (var descriptor in source)
            target.Add(descriptor);

        target.Decompose<IPipelineStep>().AddLast(Step<StepC>());

        // Descriptors are values and get copied between collections. A cursor is not: handed out ready-made it
        // would carry the collection it was composed on, and the member would land there instead - in silence,
        // with the cursor's count going up and the provider built from this collection missing it.
        Assert.Equal("A,B,C", Resolve(target));
        Assert.Equal("A,B", Resolve(source));
    }

    [Fact]
    public void ACursorTakenBeforeCompositionEditsTheComposedFamily()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();
        services.AddSingleton<IPipelineStep, StepB>();

        var cursor = services.Decompose<IPipelineStep>();
        services.Compose<IPipelineStep, PipelineComposite>();

        // Held across the composition, a cursor that still looked for plain descriptors would find one - the
        // composite's own registration - call it a member, and add beside it, which is the silent unseating.
        Assert.Equal(
            [typeof(StepA), typeof(StepB)],
            cursor.Select(member => member.ResolveImplementationType()).ToArray());

        cursor.AddLast(Step<StepC>());

        Assert.Equal("A,B,C", Resolve(services));
    }

    [Fact]
    public void Decompose_SurvivesTheCompositionOfTheFamilyItIsEditing()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();

        services.Decompose<IPipelineStep>().AddLast(Step<StepB>());
        services.Compose<IPipelineStep, PipelineComposite>();
        services.Decompose<IPipelineStep>().AddLast(Step<StepC>());

        // The same call adds a member before and after composition, and both land inside the family.
        Assert.Equal("A,B,C", Resolve(services));
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
    public void AddFirst_ComposesTheExactMemberTypesInOrder()
    {
        var services = ComposedFamily();

        services.Decompose<IPipelineStep>().AddFirst(Step<StepC>());

        using var provider = services.BuildServiceProvider();

        // The whole contract in one assertion: the singular resolve yields the composite, and the composite holds
        // the edited family as concrete instances in execution order. The sibling tests read the Name projection,
        // which would still pass if two steps merely reported the same name.
        var composite = Assert.IsType<PipelineComposite>(provider.GetRequiredService<IPipelineStep>());
        Assert.Equal(
            [typeof(StepC), typeof(StepA), typeof(StepB)],
            composite.Steps.Select(step => step.GetType()).ToArray());
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
            .AddAfter<StepA>(Step<StepD>());

        Assert.Equal("C,A,D,B", Resolve(services));
    }

    [Fact]
    public void AddFirst_RefusesAMemberTheFamilyAlreadyHas()
    {
        var services = ComposedFamily();

        // A family holds one member per implementation type, because every anchor resolves by it. A second
        // copy would make AddAfter<StepA>, Remove<StepA> and Replace<StepA> silently mean the first one.
        var exception = Assert.Throws<InvalidOperationException>(
            () => services.Decompose<IPipelineStep>().AddFirst(Step<StepA>()));

        Assert.Contains(nameof(StepA), exception.Message);
    }

    [Fact]
    public void AddLast_LeavesAMemberTheFamilyAlreadyHasWhereItIs()
    {
        var services = ComposedFamily();

        services.Decompose<IPipelineStep>().AddLast(Step<StepA>());

        // Not moved to the end, and not duplicated: it is already in the family, so there is nothing to add.
        Assert.Equal("A,B", Resolve(services));
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
    public void Compose_MixedMemberLifetimes_ComposesWithCompositeAtShortestLifetime()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();
        services.AddScoped<IPipelineStep, StepB>();

        services.Compose<IPipelineStep, PipelineComposite>();

        // The composite adopts the shortest member lifetime (Scoped); the singleton member keeps its own and
        // is shared. No captive dependency, so the scope-validating provider builds and resolves cleanly.
        var composite = services.Single(descriptor =>
            descriptor is { IsKeyedService: false } && descriptor.ServiceType == typeof(PipelineComposite));
        Assert.Equal(ServiceLifetime.Scoped, composite.Lifetime);

        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var scope = provider.CreateScope();
        Assert.Equal("A,B", scope.ServiceProvider.GetRequiredService<IPipelineStep>().Name);
    }

    [Fact]
    public void AddingAShorterLivedMemberThanTheComposite_Throws()
    {
        var services = ComposedFamily(); // all singletons, so the composite is a singleton

        // A scoped member is shorter-lived than the singleton composite - it would be captured - so it is rejected.
        var exception = Assert.Throws<InvalidOperationException>(
            () => services.Decompose<IPipelineStep>()
                .AddLast(ServiceDescriptor.Scoped<IPipelineStep, StepC>()));
        Assert.Contains(nameof(IPipelineStep), exception.Message);
    }

    [Fact]
    public void AddingALongerLivedMemberThanTheComposite_IsAllowedAndShared()
    {
        var services = new ServiceCollection();
        services.AddScoped<IPipelineStep, StepA>();
        services.AddScoped<IPipelineStep, StepB>();
        services.Compose<IPipelineStep, PipelineComposite>(); // scoped composite

        // A singleton member is longer-lived than the scoped composite - safe, it is simply shared.
        services.Decompose<IPipelineStep>().AddLast(ServiceDescriptor.Singleton<IPipelineStep, StepC>());

        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var scope = provider.CreateScope();
        Assert.Equal("A,B,C", scope.ServiceProvider.GetRequiredService<IPipelineStep>().Name);
    }

    [Fact]
    public void SingletonMemberInAScopedComposite_IsSharedAcrossScopes_NotRecreated()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();   // singleton member
        services.AddScoped<IPipelineStep, StepB>();      // scoped member makes the composite scoped
        services.Compose<IPipelineStep, PipelineComposite>();

        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var scope1 = provider.CreateScope();
        using var scope2 = provider.CreateScope();

        var composite1 = (PipelineComposite)scope1.ServiceProvider.GetRequiredService<IPipelineStep>();
        var composite2 = (PipelineComposite)scope2.ServiceProvider.GetRequiredService<IPipelineStep>();

        // Each scope gets its own scoped composite and its own scoped StepB...
        Assert.NotSame(composite1, composite2);
        Assert.NotSame(composite1.Steps.OfType<StepB>().Single(), composite2.Steps.OfType<StepB>().Single());

        // ...but the singleton StepA is created once and shared - the SAME instance goes into both composites,
        // not re-created per scoped composite.
        Assert.Same(composite1.Steps.OfType<StepA>().Single(), composite2.Steps.OfType<StepA>().Single());
    }

    [Fact]
    public void Compose_SecondTimeForSameFamily_Throws()
    {
        var services = ComposedFamily();
        services.AddSingleton<IPipelineStep, StepC>();

        var exception = Assert.Throws<InvalidOperationException>(
            () => services.Compose<IPipelineStep, PipelineComposite>());
        Assert.Contains(nameof(IPipelineStep), exception.Message);
    }

    [Fact]
    public void IsReadOnly_IsFalse()
    {
        var services = ComposedFamily();

        Assert.False(services.Decompose<IPipelineStep>().IsReadOnly);
    }

    [Fact]
    public void Count_ReflectsTheMemberCount()
    {
        var services = ComposedFamily();

        Assert.Equal(2, services.Decompose<IPipelineStep>().Count);
    }

    [Fact]
    public void IndexOf_FindsAMemberByImplementationType_FromAFreshPlainDescriptor()
    {
        var services = ComposedFamily();

        var composition = services.Decompose<IPipelineStep>();

        // Step<T>() builds a fresh plain descriptor, not the re-keyed instance stored in the family; matching is by
        // implementation type, so it still resolves to the member's position, and a non-member yields -1.
        Assert.Equal(0, composition.IndexOf(Step<StepA>()));
        Assert.Equal(1, composition.IndexOf(Step<StepB>()));
        Assert.Equal(-1, composition.IndexOf(Step<StepC>()));
    }

    [Fact]
    public void Contains_MatchesAMemberByImplementationType()
    {
        var services = ComposedFamily();

        var composition = services.Decompose<IPipelineStep>();

        Assert.True(composition.Contains(Step<StepA>()));
        Assert.False(composition.Contains(Step<StepC>()));
    }

    [Fact]
    public void Remove_ByPlainDescriptor_DropsTheMatchingMember()
    {
        var services = ComposedFamily();

        Assert.True(services.Decompose<IPipelineStep>().Remove(Step<StepA>()));

        Assert.Equal("B", Resolve(services));
    }

    [Fact]
    public void Remove_ByNonMemberDescriptor_ReturnsFalseAndChangesNothing()
    {
        var services = ComposedFamily();

        Assert.False(services.Decompose<IPipelineStep>().Remove(Step<StepC>()));

        Assert.Equal("A,B", Resolve(services));
    }

    [Fact]
    public void CopyTo_CopiesMembersInExecutionOrder()
    {
        var services = ComposedFamily();

        var target = new ServiceDescriptor[2];
        services.Decompose<IPipelineStep>().CopyTo(target, 0);

        Assert.Equal(
            [typeof(StepA), typeof(StepB)],
            target.Select(descriptor => descriptor.ResolveImplementationType()).ToArray());
    }

    [Fact]
    public void Clear_RemovesEveryMember()
    {
        var services = ComposedFamily();

        var composition = services.Decompose<IPipelineStep>();
        composition.Clear();

        // The composite still resolves; it simply has no steps left.
        Assert.Empty(composition);
        Assert.Equal("", Resolve(services));
    }

    [Fact]
    public void Insert_WithIndexPastMemberCount_Throws()
    {
        var services = ComposedFamily();

        Assert.Throws<ArgumentOutOfRangeException>(
            () => services.Decompose<IPipelineStep>().Insert(99, Step<StepC>()));
    }
}
