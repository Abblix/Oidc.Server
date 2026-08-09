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

using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.DependencyInjection;

/// <summary>
/// Provides extension methods for <see cref="IServiceCollection"/> to enhance dependency injection capabilities.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Creates an alias registration that allows resolving a service through a different interface or type.
    /// </summary>
    /// <typeparam name="TService">The service type for the alias registration.</typeparam>
    /// <typeparam name="TImplementation">The implementation service type that is already registered.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    /// <remarks>
    /// <para>
    /// This method creates an alias by cloning the source service descriptor with a new service type.
    /// The alias preserves the lifetime of the source registration (Singleton, Scoped, or Transient).
    /// </para>
    /// <para>
    /// For Singleton lifetime with factory-based registrations, ensures the same instance is returned
    /// when resolving through either the source type or the alias. For Scoped and Transient lifetimes,
    /// the alias resolves through the source service to maintain proper lifetime semantics.
    /// </para>
    /// <para>
    /// Supports both interface-to-interface aliasing (e.g., <c>AddAlias&lt;IBase, IPrimary&gt;()</c>)
    /// and interface-to-implementation aliasing (e.g., <c>AddAlias&lt;IService, ServiceImpl&gt;()</c>).
    /// </para>
    /// <para>
    /// When multiple different source services are aliased to the same target interface,
    /// <c>IEnumerable&lt;TService&gt;</c> resolution returns instances from all aliases.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no registration is found for <typeparamref name="TImplementation"/>.
    /// </exception>
    public static IServiceCollection AddAlias<TService, TImplementation>(this IServiceCollection services)
        where TImplementation : class, TService
        where TService : class
    {
        services.Add(services.BuildAliasDescriptor<TService, TImplementation>());
        return services;
    }

    /// <summary>
    /// Adds <typeparamref name="TService"/> as a SHARED-instance alias for the existing
    /// <typeparamref name="TImplementation"/> registration - unless <typeparamref name="TService"/>
    /// is already registered. Sister of <see cref="AddAlias{TService,TImplementation}"/> with
    /// <c>TryAdd</c> semantics on the alias service type: a host pre-registration of the aliased
    /// contract wins, which keeps the library-wide "host pre-registration wins" convention on
    /// singular seams whose library default is routed through an alias. Use plain
    /// <see cref="AddAlias{TService,TImplementation}"/> only where the alias must be added
    /// unconditionally (e.g. composition machinery that appends to an enumerable set).
    /// </summary>
    /// <typeparam name="TService">The service type to register the alias under.</typeparam>
    /// <typeparam name="TImplementation">The implementation type already registered as a
    /// concrete (or as another service) in the service collection.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so additional calls can be chained.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no registration is found for <typeparamref name="TImplementation"/>.
    /// </exception>
    public static IServiceCollection TryAddAlias<TService, TImplementation>(this IServiceCollection services)
        where TImplementation : class, TService
        where TService : class
    {
        services.TryAdd(services.BuildAliasDescriptor<TService, TImplementation>());
        return services;
    }

    /// <summary>
    /// Adds <typeparamref name="TService"/> to an enumerable strategy set as a SHARED-instance
    /// alias for the existing <typeparamref name="TImplementation"/> registration. Sister of
    /// <see cref="AddAlias{TService,TImplementation}"/>: same semantic of "route this service
    /// to that already-registered impl", but adds via <c>TryAddEnumerable</c> (so repeated
    /// calls dedupe on <c>(ServiceType, ImplementationType)</c>) and always uses a typed
    /// factory delegate that resolves through the source registration - guaranteeing the
    /// alias and the source share one instance.
    /// </summary>
    /// <typeparam name="TService">The enumerable service type to register the alias under.</typeparam>
    /// <typeparam name="TImplementation">The implementation type already registered as a
    /// concrete (or as another <typeparamref name="TService"/>) in the service collection.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so additional calls can be chained.</returns>
    /// <exception cref="InvalidOperationException">No registration was found for
    /// <typeparamref name="TImplementation"/>.</exception>
    public static IServiceCollection TryAddEnumerableAlias<TService, TImplementation>(this IServiceCollection services)
        where TImplementation : class, TService
        where TService : class
    {
        services.TryAddEnumerable(services.BuildAliasDescriptor<TService, TImplementation>());
        return services;
    }

    /// <summary>
    /// Builds the alias <see cref="ServiceDescriptor"/> shared by
    /// <see cref="AddAlias{TService,TImplementation}"/> and
    /// <see cref="TryAddEnumerableAlias{TService,TImplementation}"/>. Combines the two
    /// always-paired steps: locate the source registration of
    /// <typeparamref name="TImplementation"/> and produce a typed-factory descriptor that
    /// routes <typeparamref name="TService"/> through the source's ServiceType, preserving
    /// the source's lifetime so the alias and the source share an instance.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two-tier lookup of the source: a concrete registration
    /// (<c>ServiceType == TImpl</c>) wins over an alias registration
    /// (<c>ImplementationType == TImpl</c>) - without this priority a second alias-helper
    /// call would pick the previous alias as "source", capture the wrong ServiceType, and
    /// break later <c>Compose&lt;&gt;</c>-style replacements with an
    /// <see cref="InvalidCastException"/> at resolve. The fallback derives implementation
    /// type through <see cref="ResolveImplementationType"/> so the lookup works for the
    /// .NET 10 typed-factory descriptor shape produced by generic
    /// <c>AddSingleton&lt;TService, TImpl&gt;</c>.
    /// </para>
    /// <para>
    /// The 3-way switch over Lifetime exists for one reason: TryAddEnumerable's dedup
    /// compares <c>(ServiceType, ImplementationType)</c>, and ImplementationType for a
    /// factory descriptor is derived from the factory delegate's generic-arg-1. The
    /// untyped <c>ServiceDescriptor.Describe(Type, Func&lt;IServiceProvider, object&gt;, Lifetime)</c>
    /// overload bakes the factory as <c>Func&lt;IServiceProvider, object&gt;</c>, so dedup
    /// sees <c>ImplementationType = object</c>, hits the "implementationType == typeof(object)"
    /// guard, and <c>TryAddEnumerable</c> throws. The typed
    /// <c>Singleton&lt;TService, TImpl&gt;(factory)</c> / <c>Scoped&lt;TService, TImpl&gt;(factory)</c>
    /// / <c>Transient&lt;TService, TImpl&gt;(factory)</c> overloads bake
    /// <c>Func&lt;IServiceProvider, TImpl&gt;</c>, so <c>ImplementationType = TImpl</c> and
    /// repeated calls with the same TImpl dedupe correctly.
    /// <see cref="AddAlias{TService,TImplementation}"/> uses the same shape for symmetry
    /// with <see cref="TryAddEnumerableAlias{TService,TImplementation}"/>.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">No registration was found for
    /// <typeparamref name="TImplementation"/>, or its lifetime is not
    /// Singleton / Scoped / Transient.</exception>
    private static ServiceDescriptor BuildAliasDescriptor<TService, TImplementation>(this IServiceCollection services)
        where TImplementation : class, TService
        where TService : class
    {
        var source =
            services.LastOrDefault(s => s.ServiceType == typeof(TImplementation)) ??
            services.LastOrDefault(s => ResolveImplementationType(s) == typeof(TImplementation)) ??
            throw new InvalidOperationException(
                $"No registration found for {typeof(TImplementation).Name}. Register it first before creating an alias.");

        var sourceServiceType = source.ServiceType;
        return source.Lifetime switch
        {
            ServiceLifetime.Singleton => ServiceDescriptor.Singleton<TService, TImplementation>(
                sp => (TImplementation)sp.GetRequiredService(sourceServiceType)),

            ServiceLifetime.Scoped => ServiceDescriptor.Scoped<TService, TImplementation>(
                sp => (TImplementation)sp.GetRequiredService(sourceServiceType)),

            ServiceLifetime.Transient => ServiceDescriptor.Transient<TService, TImplementation>(
                sp => (TImplementation)sp.GetRequiredService(sourceServiceType)),

            _ => throw new InvalidOperationException(
                $"Unsupported lifetime '{source.Lifetime}' on the source registration of " +
                $"{typeof(TImplementation).Name}."),
        };
    }

    /// <summary>
    /// Stand-in for the internal <c>ServiceDescriptor.GetImplementationType()</c>: returns the
    /// implementation type whether the descriptor was registered with an explicit
    /// implementation type, an implementation instance, or a typed factory
    /// <c>Func&lt;IServiceProvider, TImpl&gt;</c> (.NET 10 generic AddSingleton uses the last shape,
    /// so the property alone returns null for those registrations). Supports both plain and keyed
    /// descriptors - for keyed ones the type is derived from the <c>Keyed*</c> counterparts, including
    /// the keyed factory shape <c>Func&lt;IServiceProvider, object?, TImpl&gt;</c> produced when
    /// <see cref="Compose{TInterface,TComposite}(IServiceCollection,Dependency[])"/> moves a family
    /// member into its keyed registration.
    /// </summary>
    /// <param name="descriptor">The descriptor whose implementation type to derive.</param>
    /// <returns>The implementation type, or null when it cannot be derived (untyped factory).</returns>
    public static Type? ResolveImplementationType(this ServiceDescriptor descriptor)
    {
        var (implementationType, instance, factory) = descriptor.IsKeyedService
            ? (descriptor.KeyedImplementationType,
               descriptor.KeyedImplementationInstance,
               (Delegate?)descriptor.KeyedImplementationFactory)
            : (descriptor.ImplementationType,
               descriptor.ImplementationInstance,
               (Delegate?)descriptor.ImplementationFactory);

        return implementationType
            ?? instance?.GetType()
            ?? ResolveFactoryImplementationType(factory);
    }

    /// <summary>
    /// Derives the implementation type from a factory delegate: a typed factory
    /// (<c>Func&lt;IServiceProvider, TImpl&gt;</c> or <c>Func&lt;IServiceProvider, object?, TImpl&gt;</c>)
    /// carries it as the delegate's last generic argument; object-typed factories fall back to the
    /// wrapper-origin derivation.
    /// </summary>
    private static Type? ResolveFactoryImplementationType(Delegate? factory)
    {
        if (factory == null)
            return null;

        var resultType = factory.GetType().GetGenericArguments()[^1];
        return resultType != typeof(object)
            ? resultType
            : ResolveWrapperImplementationType(factory);
    }

    /// <summary>
    /// Derives the implementation type of a delegate produced by <see cref="TypedFactoryWrapper{TImplementation}"/>.
    /// The wrapper's lambdas are target-typed by their object-typed returns, so the delegate's own generic
    /// arguments do not carry <c>TImplementation</c>; the compiler, however, is guaranteed to emit the lambda
    /// methods (and their closure classes) nested inside the generic wrapper class, so the delegate's
    /// <c>Method.DeclaringType</c> carries the wrapper's type argument.
    /// </summary>
    private static Type? ResolveWrapperImplementationType(Delegate? factory)
    {
        var declaringType = factory?.Method.DeclaringType;
        if (declaringType is not { IsConstructedGenericType: true })
            return null;

        var definition = declaringType.GetGenericTypeDefinition();
        var isWrapperType = definition == typeof(TypedFactoryWrapper<>) ||
                            definition.DeclaringType == typeof(TypedFactoryWrapper<>);
        return isWrapperType ? declaringType.GenericTypeArguments[0] : null;
    }

    /// <summary>
    /// Creates a keyed alias registration that allows resolving a service through a different interface or type with a specific key.
    /// </summary>
    /// <typeparam name="TService">The service type for the alias registration.</typeparam>
    /// <typeparam name="TSource">The source service type that is already registered.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="serviceKey">The service key to associate with the alias.</param>
    /// <param name="sourceKey">The service key of the source registration. Use null for non-keyed source.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    /// <remarks>
    /// <para>
    /// This method creates a keyed alias by cloning the source service descriptor with a new service type and key.
    /// The alias preserves the lifetime of the source registration (Singleton, Scoped, or Transient).
    /// </para>
    /// <para>
    /// For factory-based registrations, the alias resolves through the source service to maintain proper lifetime semantics.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no registration is found for <typeparamref name="TSource"/> with the specified <paramref name="sourceKey"/>.
    /// </exception>
    public static IServiceCollection AddKeyedAlias<TService, TSource>(
        this IServiceCollection services,
        object? serviceKey,
        object? sourceKey = null)
        where TService : class
        where TSource : class
    {
        services.Add(services.BuildKeyedAliasDescriptor<TService, TSource>(serviceKey, sourceKey));
        return services;
    }

    /// <summary>
    /// Creates a keyed alias registration for <typeparamref name="TService"/> under
    /// <paramref name="serviceKey"/> - unless that (service type, key) pair is already
    /// registered. Sister of <see cref="AddKeyedAlias{TService,TSource}"/> with <c>TryAdd</c>
    /// semantics on the alias identity: a pre-existing registration under the same key wins,
    /// mirroring <see cref="TryAddAlias{TService,TImplementation}"/> for keyed seams and
    /// keeping the library-wide "host pre-registration wins" convention.
    /// </summary>
    /// <typeparam name="TService">The service type for the alias registration.</typeparam>
    /// <typeparam name="TSource">The source service type that is already registered.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="serviceKey">The service key to associate with the alias.</param>
    /// <param name="sourceKey">The service key of the source registration. Use null for non-keyed source.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no registration is found for <typeparamref name="TSource"/> with the specified <paramref name="sourceKey"/>.
    /// </exception>
    public static IServiceCollection TryAddKeyedAlias<TService, TSource>(
        this IServiceCollection services,
        object? serviceKey,
        object? sourceKey = null)
        where TService : class
        where TSource : class
    {
        services.TryAdd(services.BuildKeyedAliasDescriptor<TService, TSource>(serviceKey, sourceKey));
        return services;
    }

    /// <summary>
    /// Builds the keyed alias <see cref="ServiceDescriptor"/> shared by
    /// <see cref="AddKeyedAlias{TService,TSource}"/> and
    /// <see cref="TryAddKeyedAlias{TService,TSource}"/>: locates the most recent
    /// registration of <typeparamref name="TSource"/> under <paramref name="sourceKey"/>
    /// and clones it with <typeparamref name="TService"/> and <paramref name="serviceKey"/>
    /// as the new service identity.
    /// </summary>
    private static ServiceDescriptor BuildKeyedAliasDescriptor<TService, TSource>(
        this IServiceCollection services,
        object? serviceKey,
        object? sourceKey)
        where TService : class
        where TSource : class
    {
        // Find the most recent keyed registration of TSource
        var source = services.LastOrDefault(s =>
            (s.ServiceType == typeof(TSource) || s.ImplementationType == typeof(TSource)) &&
            Equals(s.ServiceKey, sourceKey))
            ?? throw new InvalidOperationException(
                $"No registration found for {typeof(TSource).Name} with key '{sourceKey}'. " +
                $"Register it first before creating an alias.");

        // Clone the descriptor with TService as the new ServiceType and serviceKey
        return source.CloneKeyed(typeof(TService), serviceKey);
    }

    /// <summary>
    /// Creates a copy of the service descriptor with a different service type while preserving
    /// the implementation and lifetime. For factory-based registrations, resolves through the
    /// source service type to maintain same-instance semantics across all aliases.
    /// </summary>
    /// <param name="source">The source service descriptor to clone.</param>
    /// <param name="serviceType">The service type for the cloned descriptor.</param>
    /// <returns>A new service descriptor with the specified service type.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the source descriptor has an invalid configuration.</exception>
    public static ServiceDescriptor Clone(this ServiceDescriptor source, Type serviceType)
    {
        return source switch
        {
            { ImplementationType: { } type }
                => ServiceDescriptor.Describe(serviceType, type, source.Lifetime),

            { ImplementationFactory: not null }
                => ServiceDescriptor.Describe(
                    serviceType,
                    sp => sp.GetRequiredService(source.ServiceType),
                    source.Lifetime),

            { ImplementationInstance: { } instance }
                => new ServiceDescriptor(serviceType, instance),

            _ => throw new InvalidOperationException(
                $"Cannot create alias {serviceType.Name} for {source.ServiceType.Name}. " +
                $"Invalid service descriptor configuration.")
        };
    }

    /// <summary>
    /// Creates a copy of the keyed service descriptor with a different service type and key while preserving
    /// the implementation and lifetime. For factory-based registrations, resolves through the
    /// source service type and key to maintain same-instance semantics across all aliases.
    /// </summary>
    /// <param name="source">The source service descriptor to clone.</param>
    /// <param name="serviceType">The service type for the cloned descriptor.</param>
    /// <param name="serviceKey">The service key for the cloned descriptor.</param>
    /// <returns>A new keyed service descriptor with the specified service type and key.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the source descriptor has an invalid configuration.</exception>
    public static ServiceDescriptor CloneKeyed(this ServiceDescriptor source, Type serviceType, object? serviceKey)
    {
        return source switch
        {
            // Check if source is keyed
            { IsKeyedService: true, KeyedImplementationType: not null } or
            { IsKeyedService: true, KeyedImplementationFactory: not null }
                => ServiceDescriptor.DescribeKeyed(
                    serviceType,
                    serviceKey,
                    (sp, _) => sp.GetRequiredKeyedService(source.ServiceType, source.ServiceKey),
                    source.Lifetime),

            { IsKeyedService: true, KeyedImplementationInstance: { } instance }
                => ServiceDescriptor.KeyedSingleton(serviceType, serviceKey, instance),

            // Handle non-keyed source
            { ImplementationType: { } type }
                => ServiceDescriptor.DescribeKeyed(serviceType, serviceKey, type, source.Lifetime),

            { ImplementationFactory: not null }
                => ServiceDescriptor.DescribeKeyed(
                    serviceType,
                    serviceKey,
                    (sp, _) => sp.GetRequiredService(source.ServiceType),
                    source.Lifetime),

            { ImplementationInstance: { } instance }
                => ServiceDescriptor.KeyedSingleton(serviceType, serviceKey, instance),

            _ => throw new InvalidOperationException(
                $"Cannot create keyed alias {serviceType.Name} for keyed {source.ServiceType.Name}. " +
                $"Invalid service descriptor configuration.")
        };
    }

    /// <summary>
    /// Composes a service type with multiple implementations into a single composite service.
    /// </summary>
    /// <typeparam name="TInterface">The interface type to be composed.</typeparam>
    /// <typeparam name="TComposite">The composite implementation type.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="dependencies">The dependencies required by the composite service.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    /// <remarks>
    /// This method replaces multiple service registrations of the same type with a single composite registration.
    /// The composite type must have a constructor that accepts an array of the interface type.
    /// The existing registrations are moved into keyed registrations (key = the composite type) that the
    /// composite resolves in registration order; being keyed also hides them from plain resolution, so the
    /// singular resolve yields only the composite. The family thus remains descriptor data in the collection
    /// rather than a snapshot captured in a closure: <see cref="Decompose{TInterface}(IServiceCollection)"/> returns a live cursor
    /// over that data, and edits through it reach the composite at resolve - without the host ever naming the
    /// composite type. Members keep their own lifetimes and the composite adopts the shortest among them, so a
    /// longer-lived member is simply shared; only a member shorter-lived than the composite is rejected, since
    /// a composite may not capture something that dies before it.
    /// </remarks>
    public static IServiceCollection Compose<TInterface, TComposite>(
        this IServiceCollection services,
        params Dependency[] dependencies)
        where TInterface : class where TComposite : class, TInterface
    {
        services.EnsureNotComposed(typeof(TInterface));

        var members = services
            .Where(descriptor => descriptor is { IsKeyedService: false } &&
                                 descriptor.ServiceType == typeof(TInterface))
            .ToArray();

        // One member is a family too. Skipping it would leave the caller believing a composite exists where
        // none does, and everything downstream reads that state differently from the caller: the guard against
        // a second composition has nothing to find, the cursor takes the loose path, and the lone member
        // answers the singular resolve directly - without the routing and the closed door the composite is
        // there to provide. An empty family is the one case with nothing to compose.
        if (members.Length == 0)
            return services;

        foreach (var member in members)
            services.Remove(member);

        return services.ComposeFamily<TInterface>(typeof(TComposite), members, dependencies);
    }

    /// <summary>
    /// Opens the <typeparamref name="TInterface"/> family for in-place editing: returns a live
    /// <see cref="IComposition{TInterface}"/> cursor over its members. Insert, remove or reorder through the
    /// cursor and the change is live - a composed family's composite reads its members via
    /// <c>GetKeyedServices</c> at resolve, so the edit takes effect with no separate recompose.
    /// </summary>
    /// <typeparam name="TInterface">The family interface type.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> holding the family.</param>
    /// <returns>A live cursor over the family's members, in execution order.</returns>
    /// <remarks>
    /// Whether the family has been composed is the cursor's business, not the caller's: editing its members is
    /// the only reason to ask for one. Composed, the members live as keyed descriptors whose service key is the
    /// composite type, which both hides them from plain resolution and names the composite they belong to.
    /// Uncomposed, they are the plain descriptors of the interface, and a later <c>Compose</c> takes them as
    /// they stand. The cursor edits whichever of the two the family currently holds, so the same call adds a
    /// member before and after composition.
    /// <see cref="IComposition{TInterface}"/> adds position-aware sugar (<c>AddAfter</c>, <c>AddBefore</c>,
    /// <c>Remove</c>, ...); anchors are matched by implementation type via
    /// <see cref="ResolveImplementationType"/>, which identifies a member even when it was registered through a
    /// typed factory (e.g. by <see cref="TryAddEnumerableAlias{TService,TImplementation}"/>).
    /// <code>
    /// services.Decompose&lt;IPipelineStep&gt;()
    ///     .AddAfter&lt;BuiltInStep&gt;(ServiceDescriptor.Singleton&lt;IPipelineStep, MyStep&gt;())
    ///     .Remove&lt;UnwantedStep&gt;();
    /// </code>
    /// </remarks>
    /// <exception cref="InvalidOperationException">The family is composed but its composite registration is
    /// missing, which no sequence of calls on this API produces.</exception>
    public static IComposition<TInterface> Decompose<TInterface>(this IServiceCollection services)
        where TInterface : class
    {
        // A family that has not been composed is still a family: its members are the plain descriptors of the
        // interface, and the cursor edits those. The caller wanted to change the family's members, which is the
        // only reason to be here, and whether a composite exists yet is not its business.
        return services.OpenComposition<TInterface>(serviceKey: null)
               ?? new Composition<TInterface>(services, memberKey: null, lifetime: null);
    }

    /// <summary>
    /// The members of the <typeparamref name="TInterface"/> family as the container will run them - the
    /// resolve-time counterpart of <see cref="Decompose{TInterface}(IServiceCollection)"/>, which edits the
    /// same family before the container is built.
    /// </summary>
    /// <remarks>
    /// Whether the family was composed is this method's business, not the caller's: composed, the members are
    /// keyed and hidden from plain resolution; loose, they are the plain registrations. Asking for them by the
    /// key composition happens to use is what a caller must not do, because a key that is merely out of date
    /// answers with an empty set rather than an error - and an empty set reads as a family with nothing in it.
    /// <para>
    /// For that reason an empty family is refused rather than returned. A caller that wants a possibly-empty
    /// answer is asking about registrations rather than about a family, and
    /// <see cref="ServiceProviderServiceExtensions.GetServices{T}(IServiceProvider)"/> is that question.
    /// </para>
    /// </remarks>
    /// <typeparam name="TInterface">The family interface.</typeparam>
    /// <param name="serviceProvider">The provider built from the collection the family lives in.</param>
    /// <param name="serviceKey">The key a keyed family lives under, or null for a plain family.</param>
    /// <returns>The family's members, in execution order.</returns>
    /// <exception cref="InvalidOperationException">The family has no members.</exception>
    public static IReadOnlyList<TInterface> Decompose<TInterface>(
        this IServiceProvider serviceProvider, object? serviceKey = null)
        where TInterface : class
    {
        var key = new CompositionKey(typeof(TInterface), serviceKey);

        IEnumerable<TInterface> GetRegisteredServices() => serviceKey is null
            ? serviceProvider.GetServices<TInterface>()
            : serviceProvider.GetKeyedServices<TInterface>(serviceKey);

        var family = (serviceProvider.GetKeyedService<IComposition<TInterface>>(key) is not null
            ? serviceProvider.GetKeyedServices<TInterface>(key)
            : GetRegisteredServices()).ToArray();
        if (family.Length == 0)
        {
            throw new InvalidOperationException(
                $"The {typeof(TInterface).Name} family has no members" +
                (serviceKey is null ? "." : $" under the key '{serviceKey}'."));
        }

        return family;
    }

    /// <summary>
    /// Composes keyed implementations of <typeparamref name="TInterface"/> registered under
    /// <paramref name="serviceKey"/> into a single composite resolvable under that same key - the keyed
    /// counterpart of <see cref="Compose{TInterface,TComposite}(IServiceCollection,Dependency[])"/>.
    /// The members move to keyed registrations under the family's own key, so same-interface families under
    /// different keys stay isolated and the family remains editable descriptor data for
    /// <see cref="DecomposeKeyed{TInterface}"/>.
    /// </summary>
    /// <typeparam name="TInterface">The interface type to be composed.</typeparam>
    /// <typeparam name="TComposite">The composite implementation type.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="serviceKey">The service key whose registrations form the family.</param>
    /// <param name="dependencies">The dependencies required by the composite service.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    /// <exception cref="InvalidOperationException">The family is already composed under this key.</exception>
    public static IServiceCollection ComposeKeyed<TInterface, TComposite>(
        this IServiceCollection services,
        object serviceKey,
        params Dependency[] dependencies)
        where TInterface : class where TComposite : class, TInterface
    {
        ArgumentNullException.ThrowIfNull(serviceKey);
        services.EnsureNotComposedKeyed(typeof(TInterface), typeof(TComposite), serviceKey);

        var members = services
            .Where(descriptor => descriptor is { IsKeyedService: true } &&
                                 descriptor.ServiceType == typeof(TInterface) &&
                                 Equals(descriptor.ServiceKey, serviceKey))
            .ToArray();

        // As in Compose: one member is a family, none is not.
        if (members.Length == 0)
            return services;

        foreach (var member in members)
            services.Remove(member);

        return services.ComposeKeyedFamily<TInterface>(typeof(TComposite), serviceKey, members, dependencies);
    }

    /// <summary>
    /// Opens the keyed <typeparamref name="TInterface"/> family for in-place editing: returns a live
    /// <see cref="IComposition{TInterface}"/> cursor over its members. Insert, remove or reorder through the
    /// cursor and the change is live - a composed family's keyed composite reads its members via
    /// <c>GetKeyedServices</c> at resolve, so the edit takes effect with no separate recompose. Uncomposed, the
    /// members are the descriptors registered under the service key itself, and the cursor edits those.
    /// </summary>
    /// <typeparam name="TInterface">The composed interface type.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> holding the composed family.</param>
    /// <param name="serviceKey">The service key the family was composed under.</param>
    /// <returns>A live cursor over the family's members, in execution order.</returns>
    /// <remarks>
    /// The mechanics mirror <see cref="Decompose{TInterface}(IServiceCollection)"/>, except the family's key carries the service
    /// key too, so pipelines of the same interface under different keys stay isolated.
    /// <see cref="IComposition{TInterface}"/> adds the same position-aware sugar
    /// (<c>AddAfter</c>, <c>Remove</c>, ...).
    /// </remarks>
    /// <exception cref="InvalidOperationException">The family is composed under this key but its composite
    /// registration is missing, which no sequence of calls on this API produces.</exception>
    public static IComposition<TInterface> DecomposeKeyed<TInterface>(
        this IServiceCollection services,
        object serviceKey)
        where TInterface : class
    {
        ArgumentNullException.ThrowIfNull(serviceKey);

        // Uncomposed, the family's members are the descriptors registered under the service key itself, and the
        // cursor edits those - the keyed mirror of what Decompose does for a plain family.
        return services.OpenComposition<TInterface>(serviceKey)
               ?? new Composition<TInterface>(services, serviceKey, lifetime: null);
    }

    /// <summary>
    /// Fails loud when the <paramref name="interfaceType"/> family has already been composed into
    /// <paramref name="compositeType"/> under <paramref name="serviceKey"/> - the keyed sibling of
    /// <see cref="EnsureNotComposed"/>. The sanctioned way to edit an already-composed keyed family is
    /// <see cref="DecomposeKeyed{TInterface}"/> and editing the live cursor it returns.
    /// </summary>
    private static void EnsureNotComposedKeyed(
        this IServiceCollection services, Type interfaceType, Type compositeType, object serviceKey)
    {
        // The cursor a composition stores under the family's identity, so this asks about this family under
        // this key and nothing else - two families of the same interface under different keys are separate
        // compositions and neither blocks the other.
        var compositionType = typeof(IComposition<>).MakeGenericType(interfaceType);
        var key = new CompositionKey(interfaceType, serviceKey);

        var alreadyComposed = services.Any(
            descriptor => descriptor is { IsKeyedService: true } &&
                          descriptor.ServiceType == compositionType &&
                          Equals(descriptor.ServiceKey, key));
        if (alreadyComposed)
        {
            throw new InvalidOperationException(
                $"{compositeType.Name} is already composed for the {interfaceType.Name} pipeline keyed by " +
                $"'{serviceKey}'. Composing it a second time would build a self-referential composite that " +
                $"deadlocks on the first resolve. Call {nameof(DecomposeKeyed)} and edit the live cursor it " +
                "returns.");
        }
    }

    /// <summary>
    /// The keyed composition tail over <see cref="KeyFamilyMembers{TInterface}"/>: keys the members by the
    /// family's key and registers the composite as a keyed service under the family's original service key.
    /// The members must already be detached from the collection.
    /// </summary>
    private static IServiceCollection ComposeKeyedFamily<TInterface>(
        this IServiceCollection services,
        Type compositeType,
        object serviceKey,
        ServiceDescriptor[] members,
        Dependency[] dependencies)
        where TInterface : class
    {
        var key = new CompositionKey(typeof(TInterface), serviceKey);
        var compositeFactory = services.KeyFamilyMembers<TInterface>(
            compositeType, key, members, dependencies, out var lifetime);

        services.StoreComposition<TInterface>(key, lifetime);

        // Register the composite as a keyed service under the original key. The factory is typed by the
        // composite (via TypedFactoryWrapper), so ResolveImplementationType identifies it and
        // DecomposeKeyed can strip it.
        services.Add(new ServiceDescriptor(
            typeof(TInterface), serviceKey,
            CreateTypedFactoryWrapper(compositeType).WrapKeyed(compositeFactory), lifetime));

        return services;
    }

    /// <summary>
    /// The cursor a composition left over the <typeparamref name="TInterface"/> family, or null when the family
    /// has never been composed.
    /// </summary>
    /// <remarks>
    /// The cursor holds no copy of the member list, so the one stored at composition time stays correct for the
    /// life of the collection. Storing it rather than the composite type is what lets a family answer for
    /// itself: every member can be removed through the cursor, and a composite derived from the members would
    /// then be underivable, leaving an emptied family reading as one that was never composed.
    /// </remarks>
    private static IComposition<TInterface>? OpenComposition<TInterface>(
        this IServiceCollection services, object? serviceKey)
        where TInterface : class
    {
        var key = new CompositionKey(typeof(TInterface), serviceKey);

        var stored = services.FirstOrDefault(
                descriptor => descriptor is { IsKeyedService: true } &&
                              descriptor.ServiceType == typeof(IComposition<TInterface>) &&
                              Equals(descriptor.ServiceKey, key))
            ?.KeyedImplementationInstance;

        if (stored is IComposition<TInterface> composition)
            return composition;

        // A member carries a CompositionKey, which nothing outside this assembly can build, so members present
        // without their cursor mean the cursor was removed from the collection. Answering with a fresh one
        // would read the family as never composed and take the composite - a registration of the interface
        // like any other - for a member of the family it heads.
        if (services.Any(descriptor => descriptor.ServiceType == typeof(TInterface) &&
                                       Equals(descriptor.ServiceKey, key)))
        {
            throw new InvalidOperationException(
                $"The {typeof(TInterface).Name} family is composed, but the cursor over its members is missing "
                + "from the collection, so its members can no longer be told apart from the composite over "
                + "them. Something removed it; no sequence of calls on this API does.");
        }

        return null;
    }

    /// <summary>
    /// Stores the cursor over a family just composed, under the family's identity, so the family answers for
    /// itself rather than being inferred from registrations that its own cursor can remove.
    /// </summary>
    private static void StoreComposition<TInterface>(
        this IServiceCollection services, CompositionKey key, ServiceLifetime lifetime)
        where TInterface : class
        => services.Add(new ServiceDescriptor(
            typeof(IComposition<TInterface>), key, new Composition<TInterface>(services, key, lifetime)));

    /// <summary>
    /// Fails loud when the <paramref name="interfaceType"/> family has already been composed. A second
    /// composition would rebuild the composite over a member set that already contains the alias to the first
    /// composite, so the new composite would resolve one of its own children back to itself - a
    /// self-referential singleton that deadlocks on first resolve. This happens when two registration methods
    /// each compose the same family, or when a caller composes a family that a registration method it also
    /// calls composes for it. The sanctioned way to edit an already-composed family is
    /// <see cref="Decompose{TInterface}(IServiceCollection)"/> and editing the live cursor it returns.
    /// </summary>
    /// <remarks>
    /// The question is whether THIS FAMILY is composed, which is what the stored cursor answers - not whether
    /// the composite type is registered. Those differ exactly when the second composition names a different
    /// composite, and that is the case the deadlock is reachable through: the guard lets it past, and the
    /// first composite's own alias becomes a member of the family it heads.
    /// </remarks>
    private static void EnsureNotComposed(this IServiceCollection services, Type interfaceType)
    {
        var compositionType = typeof(IComposition<>).MakeGenericType(interfaceType);
        var key = new CompositionKey(interfaceType, ServiceKey: null);

        var alreadyComposed = services.Any(
            descriptor => descriptor is { IsKeyedService: true } &&
                          descriptor.ServiceType == compositionType &&
                          Equals(descriptor.ServiceKey, key));

        if (alreadyComposed)
        {
            throw new InvalidOperationException(
                $"The {interfaceType.Name} family is already composed. Composing it a second time would build " +
                "a self-referential composite that deadlocks on the first resolve. Compose the family once, " +
                $"and add every {interfaceType.Name} member through {nameof(Decompose)}, whose cursor edits " +
                "the family whether or not it has been composed yet.");
        }
    }

    /// <summary>
    /// The shared composition core: keys the members by the family interface, registers the composite over
    /// them and records the family. The members must already be detached from the collection.
    /// </summary>
    private static IServiceCollection ComposeFamily<TInterface>(
        this IServiceCollection services,
        Type compositeType,
        ServiceDescriptor[] members,
        Dependency[] dependencies)
        where TInterface : class
    {
        var key = new CompositionKey(typeof(TInterface), ServiceKey: null);
        var compositeFactory = services.KeyFamilyMembers<TInterface>(
            compositeType, key, members, dependencies, out var lifetime);

        services.StoreComposition<TInterface>(key, lifetime);

        // Register the composite type itself (so it can be aliased and located by Decompose) and the
        // interface routing to it. The alias factory is typed by the composite (via TypedFactoryWrapper),
        // so ResolveImplementationType identifies it and Decompose can strip it.
        services.Add(ServiceDescriptor.Describe(compositeType, compositeFactory, lifetime));
        services.Add(ServiceDescriptor.Describe(
            typeof(TInterface), CreateTypedFactoryWrapper(compositeType).WrapResolve(), lifetime));

        return services;
    }

    /// <summary>
    /// The composition core shared by the plain and keyed families: moves the detached members into keyed
    /// registrations under <paramref name="memberKey"/> (sharing the composite's lifetime, so member
    /// instances live exactly as long as the composite that consumes them) and returns the factory that
    /// materializes the composite over them.
    /// </summary>
    private static Func<IServiceProvider, object> KeyFamilyMembers<TInterface>(
        this IServiceCollection services,
        Type compositeType,
        object memberKey,
        ServiceDescriptor[] members,
        Dependency[] dependencies,
        out ServiceLifetime lifetime)
        where TInterface : class
    {
        var parameterType = ResolveCompositeParameterType(compositeType, typeof(TInterface));

        // The composite adopts the SHORTEST lifetime among its members, so it never outlives one of them -
        // a composite that outlived a member would capture a shorter-lived service. Members keep their OWN
        // lifetime: a longer-lived member (a singleton, say) is simply shared across every composite instance,
        // which is safe (the composite is the shorter-lived one) and cheaper than promoting it. ServiceLifetime
        // orders Singleton < Scoped < Transient by increasing ephemerality, so Max picks the shortest-lived.
        lifetime = members.Max(descriptor => descriptor.Lifetime);

        foreach (var member in members)
            services.Add(member.ToKeyedFamilyMember(memberKey, member.Lifetime));

        return serviceProvider =>
        {
            var serviceInstances = serviceProvider
                .GetKeyedServices<TInterface>(memberKey)
                .ToArray();

            var serviceDependencies = Dependency.Override(parameterType, serviceInstances);
            return serviceProvider.CreateService(compositeType, dependencies.Append(serviceDependencies));
        };
    }

    /// <summary>
    /// Locates the composite's public constructor parameter that accepts the family members
    /// (an array of the interface type or a compatible collection).
    /// </summary>
    private static Type ResolveCompositeParameterType(Type compositeType, Type interfaceType)
        => compositeType
               .GetConstructors(BindingFlags.Instance | BindingFlags.Public)
               .SelectMany(constructor => constructor.GetParameters(),
                   (_, parameterInfo) => parameterInfo.ParameterType)
               .FirstOrDefault(type => type.IsAssignableFrom(interfaceType.MakeArrayType()))
           ?? throw new InvalidOperationException(
               $"The type {compositeType.FullName} has no public constructor that accepts " +
               $"{interfaceType.FullName}[]");

    private static ITypedFactoryWrapper CreateTypedFactoryWrapper(Type implementationType)
        => (ITypedFactoryWrapper)Activator.CreateInstance(
            typeof(TypedFactoryWrapper<>).MakeGenericType(implementationType))!;

    /// <summary>
    /// Converts a family-member descriptor into the keyed form used by the composed family. Type- and
    /// instance-based descriptors translate directly; factory-based descriptors are wrapped into a keyed
    /// factory typed by the member's implementation type, so <see cref="ResolveImplementationType"/> keeps
    /// identifying the member after the move. Descriptors that are already keyed (returned by
    /// <see cref="Decompose{TInterface}(IServiceCollection)"/>) are re-keyed with the family key and lifetime.
    /// </summary>
    internal static ServiceDescriptor ToKeyedFamilyMember(
        this ServiceDescriptor descriptor,
        object serviceKey,
        ServiceLifetime lifetime)
    {
        if (descriptor.IsKeyedService)
        {
            if (descriptor.KeyedImplementationType != null)
            {
                return new ServiceDescriptor(
                    descriptor.ServiceType, serviceKey, descriptor.KeyedImplementationType, lifetime);
            }

            if (descriptor.KeyedImplementationInstance != null)
            {
                return new ServiceDescriptor(
                    descriptor.ServiceType, serviceKey, descriptor.KeyedImplementationInstance);
            }

            return new ServiceDescriptor(
                descriptor.ServiceType, serviceKey, descriptor.KeyedImplementationFactory!, lifetime);
        }

        if (descriptor.ImplementationType != null)
            return new ServiceDescriptor(descriptor.ServiceType, serviceKey, descriptor.ImplementationType, lifetime);

        if (descriptor.ImplementationInstance != null)
            return new ServiceDescriptor(descriptor.ServiceType, serviceKey, descriptor.ImplementationInstance);

        var factory = descriptor.ImplementationFactory!;
        var implementationType = descriptor.ResolveImplementationType();
        if (implementationType == null || implementationType == typeof(object))
        {
            return new ServiceDescriptor(
                descriptor.ServiceType,
                serviceKey,
                (serviceProvider, _) => factory(serviceProvider),
                lifetime);
        }

        return new ServiceDescriptor(
            descriptor.ServiceType, serviceKey,
            CreateTypedFactoryWrapper(implementationType).WrapKeyed(factory), lifetime);
    }

    /// <summary>
    /// Converts a family-member descriptor into the PLAIN form an uncomposed family holds - the mirror of
    /// <see cref="ToKeyedFamilyMember"/>, used when the cursor edits a family that has not been composed.
    /// A descriptor that is already plain is its own member form. A keyed one is unkeyed, and a keyed factory
    /// is re-wrapped so <see cref="ResolveImplementationType"/> keeps identifying the member afterwards.
    /// </summary>
    internal static ServiceDescriptor ToPlainFamilyMember(
        this ServiceDescriptor descriptor,
        ServiceLifetime lifetime)
    {
        if (!descriptor.IsKeyedService)
            return descriptor;

        if (descriptor.KeyedImplementationType != null)
            return new ServiceDescriptor(descriptor.ServiceType, descriptor.KeyedImplementationType, lifetime);

        if (descriptor.KeyedImplementationInstance != null)
            return new ServiceDescriptor(descriptor.ServiceType, descriptor.KeyedImplementationInstance);

        var keyedFactory = descriptor.KeyedImplementationFactory!;
        var serviceKey = descriptor.ServiceKey;
        Func<IServiceProvider, object> factory = serviceProvider => keyedFactory(serviceProvider, serviceKey);

        var implementationType = descriptor.ResolveImplementationType();
        if (implementationType == null || implementationType == typeof(object))
            return new ServiceDescriptor(descriptor.ServiceType, factory, lifetime);

        return new ServiceDescriptor(
            descriptor.ServiceType, CreateTypedFactoryWrapper(implementationType).WrapPlain(factory), lifetime);
    }

    private interface ITypedFactoryWrapper
    {
        Func<IServiceProvider, object?, object> WrapKeyed(Func<IServiceProvider, object> factory);
        Func<IServiceProvider, object> WrapPlain(Func<IServiceProvider, object> factory);
        Func<IServiceProvider, object> WrapResolve();
    }

    /// <summary>
    /// Produces factory delegates that carry <typeparamref name="TImplementation"/> in their origin: the
    /// compiler emits the lambda methods (and closure classes) nested inside this generic class, so
    /// <see cref="ResolveImplementationType"/> derives the implementation type from the delegate's
    /// <c>Method.DeclaringType</c>.
    /// </summary>
    private sealed class TypedFactoryWrapper<TImplementation> : ITypedFactoryWrapper
        where TImplementation : class
    {
        public Func<IServiceProvider, object?, object> WrapKeyed(Func<IServiceProvider, object> factory)
            => (serviceProvider, _) => (TImplementation)factory(serviceProvider);

        public Func<IServiceProvider, object> WrapPlain(Func<IServiceProvider, object> factory)
            => serviceProvider => (TImplementation)factory(serviceProvider);

        public Func<IServiceProvider, object> WrapResolve()
            => serviceProvider => serviceProvider.GetRequiredService<TImplementation>();
    }

    /// <summary>
    /// Decorates a registered service with a decorator implementation.
    /// </summary>
    /// <typeparam name="TInterface">The service type to be decorated.</typeparam>
    /// <typeparam name="TDecorator">The decorator implementation type.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="dependencies">The dependencies required by the decorator.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    /// <remarks>
    /// The decorator pattern allows you to add behavior to existing service implementations without modifying their code.
    /// The decorator wraps the original service and preserves its lifetime registration.
    /// The decorator must implement the same interface as the service being decorated.
    /// </remarks>
    public static IServiceCollection Decorate<TInterface, TDecorator>(
        this IServiceCollection services,
        params Dependency[] dependencies)
        where TInterface : class where TDecorator : class, TInterface
    {
        return services.DecorateKeyed<TInterface, TDecorator>(serviceKey: null, dependencies: dependencies);
    }

    /// <summary>
    /// Decorates a registered keyed service with a decorator implementation.
    /// If no keyed service is found, falls back to decorating the non-keyed service
    /// and registers the result as a keyed service.
    /// </summary>
    /// <typeparam name="TInterface">The service type to be decorated.</typeparam>
    /// <typeparam name="TDecorator">The decorator implementation type.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="serviceKey">The service key for the decorated service registration.</param>
    /// <param name="dependencies">The dependencies required by the decorator.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    /// <remarks>
    /// This method allows decoration of keyed services registered using the keyed service APIs.
    /// If the keyed service is not found, it falls back to decorating the non-keyed service
    /// and registers the decorator as a keyed service. This is useful when you want to create
    /// a keyed variant of an existing non-keyed service with additional behavior.
    /// The decorator will wrap the existing implementation while preserving the service lifetime.
    /// </remarks>
    public static IServiceCollection DecorateKeyed<TInterface, TDecorator>(
        this IServiceCollection services,
        object? serviceKey,
        params Dependency[] dependencies)
        where TInterface : class where TDecorator : class, TInterface
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(dependencies);

        ServiceDescriptor? fallbackService = null;

        // First, try to find existing keyed service
        for (var i = services.Count - 1; 0 <= i; i--)
        {
            if (services[i].ServiceType != typeof(TInterface))
                continue;

            if (Equals(services[i].ServiceKey, serviceKey))
            {
                services[i] = services[i].Decorate<TInterface, TDecorator>(serviceKey, dependencies);
                return services;
            }

            if (services[i].ServiceKey == null)
            {
                fallbackService = services[i];
            }
        }

        // Fallback: find non-keyed service and create a keyed decorated version
        if (fallbackService != null)
        {
            services.Add(fallbackService.Decorate<TInterface, TDecorator>(serviceKey, dependencies));
            return services;
        }

        throw new InvalidOperationException(
            $"No service of type {typeof(TInterface).FullName} " +
            $"{(serviceKey != null ? $"with key '{serviceKey}' or without key " : "")}" +
            "has been registered. Cannot decorate a service that does not exist.");
    }

    /// <summary>
    /// Creates a new service descriptor that wraps the original service with a decorator.
    /// </summary>
    /// <typeparam name="TInterface">The service type being decorated.</typeparam>
    /// <typeparam name="TDecorator">The decorator type that implements the interface.</typeparam>
    /// <param name="serviceDescriptor">The original service descriptor to decorate.</param>
    /// <param name="serviceKey">The service key for the decorated service. If null, uses the original service's key.</param>
    /// <param name="dependencies">Additional dependencies required by the decorator.</param>
    /// <returns>A new <see cref="ServiceDescriptor"/> with the decorated implementation.</returns>
    private static ServiceDescriptor Decorate<TInterface, TDecorator>(
        this ServiceDescriptor serviceDescriptor, object? serviceKey, Dependency[] dependencies)
        where TInterface : class where TDecorator : class, TInterface
    {
        return ServiceDescriptor.DescribeKeyed(
            serviceDescriptor.ServiceType,
            serviceKey,
            (serviceProvider, _) =>
            {
                var instance = Dependency.Override((TInterface)serviceProvider.CreateService(serviceDescriptor));
                return serviceProvider.CreateService<TDecorator>(dependencies.Append(instance));
            },
            serviceDescriptor.Lifetime);
    }

    /// <summary>
    /// Appends an element to the end of the array.
    /// </summary>
    /// <typeparam name="T">The type of elements in the array.</typeparam>
    /// <param name="source">The source array.</param>
    /// <param name="element">The element to append.</param>
    /// <returns>A new array with the appended element, or a resized array if the source had elements.</returns>
    private static T[] Append<T>(this T[] source, T element)
    {
        switch (source)
        {
            case { Length: > 0 }:
                Array.Resize(ref source, source.Length + 1);
                source[^1] = element;
                return source;

            default:
                return [element];
        }
    }

    /// <summary>
    /// Resolves or creates an instance from a <see cref="ServiceDescriptor"/> using the specified service provider.
    /// </summary>
    /// <param name="serviceProvider">The service provider to resolve dependencies from.</param>
    /// <param name="descriptor">The service descriptor to use.</param>
    /// <returns>An instance of the service described by the descriptor.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown if the descriptor does not contain a valid instance, factory, or type.
    /// </exception>
    /// <remarks>
    /// Helps simulate or replicate DI container behavior for specific descriptors.
    /// </remarks>
    private static object CreateService(this IServiceProvider serviceProvider, ServiceDescriptor descriptor)
    {
        return descriptor switch
        {
            // Non-keyed service patterns
            { ImplementationInstance: { } instance } => instance,
            { ImplementationFactory: { } factory } => factory(serviceProvider),
            { ImplementationType: { } type } => ActivatorUtilities.GetServiceOrCreateInstance(serviceProvider, type),

            // Keyed service patterns
            { KeyedImplementationInstance: { } instance } => instance,
            { KeyedImplementationFactory: { } factory } => factory(serviceProvider, descriptor.ServiceKey),
            { KeyedImplementationType: { } type } => ActivatorUtilities.GetServiceOrCreateInstance(serviceProvider, type),

            _ => throw new InvalidOperationException($"Unable to create instance of {descriptor.ServiceType.FullName}")
        };
    }

    /// <summary>
    /// Creates an instance of the specified service type <typeparamref name="T"/> using the provided dependencies.
    /// </summary>
    /// <typeparam name="T">The type of service to create.</typeparam>
    /// <param name="serviceProvider">The service provider to resolve required services from.</param>
    /// <param name="dependencies">A list of explicitly provided dependencies.</param>
    /// <returns>An instance of type <typeparamref name="T"/>.</returns>
    /// <remarks>
    /// This overload simplifies strongly typed creation of services with custom dependency injection.
    /// </remarks>
    public static T CreateService<T>(this IServiceProvider serviceProvider, params Dependency[] dependencies)
    {
        return (T)serviceProvider.CreateService(typeof(T), dependencies);
    }

    /// <summary>
    /// Creates an instance of the specified type using the provided dependencies.
    /// </summary>
    /// <param name="serviceProvider">The service provider to resolve required services from.</param>
    /// <param name="type">The type of service to create.</param>
    /// <param name="dependencies">A list of explicitly provided dependencies.</param>
    /// <returns>An instance of the specified <paramref name="type"/>.</returns>
    /// <remarks>
    /// This method allows partial control over dependency injection by mixing resolved and custom parameters.
    /// Useful in plugin scenarios, factory setups, or advanced test setups.
    /// </remarks>
    public static object CreateService(
        this IServiceProvider serviceProvider,
        Type type,
        params Dependency[] dependencies)
    {
        var factory = ActivatorUtilities.CreateFactory(type, Array.ConvertAll(dependencies, d => d.Type));
        return factory(serviceProvider, Array.ConvertAll(dependencies, d => d.Factory(serviceProvider)));
    }

    /// <summary>
    /// Registers a transient service of the type specified in <typeparamref name="T"/> with custom dependencies.
    /// Transient services are created each time they are requested.
    /// </summary>
    /// <typeparam name="T">The service type to register.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="dependencies">The dependencies required by the service.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    /// <remarks>
    /// This overload is useful when the service type and implementation type are the same.
    /// </remarks>
    public static IServiceCollection AddTransient<T>(this IServiceCollection services, params Dependency[] dependencies)
        where T : class
    {
        return services.AddTransient(sp => sp.CreateService<T>(dependencies));
    }

    /// <summary>
    /// Registers a transient service with the implementation type specified in <typeparamref name="TImplementation"/>
    /// and the service type specified in <typeparamref name="TService"/> with custom dependencies.
    /// Transient services are created each time they are requested.
    /// </summary>
    /// <typeparam name="TService">The type of the service to add.</typeparam>
    /// <typeparam name="TImplementation">The type of the implementation to use.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="dependencies">The dependencies required by the service.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddTransient<TService, TImplementation>(this IServiceCollection services,
        params Dependency[] dependencies)
        where TService : class
        where TImplementation : class, TService
    {
        return services.AddTransient<TService, TImplementation>(sp => sp.CreateService<TImplementation>(dependencies));
    }

    /// <summary>
    /// Registers a scoped service of the type specified in <typeparamref name="T"/> with custom dependencies.
    /// A scoped service is created once per request within the scope.
    /// </summary>
    /// <typeparam name="T">The type of the service to add.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="dependencies">An array of <see cref="Dependency"/> objects representing additional dependencies
    /// required by the service.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddScoped<T>(this IServiceCollection services, params Dependency[] dependencies)
        where T : class
    {
        return services.AddScoped(sp => sp.CreateService<T>(dependencies));
    }

    /// <summary>
    /// Registers a scoped service with the implementation type specified in <typeparamref name="TImplementation"/>
    /// and the service type specified in <typeparamref name="TService"/> with custom dependencies.
    /// A scoped service is created once per request within the scope.
    /// </summary>
    /// <typeparam name="TService">The type of the service to add.</typeparam>
    /// <typeparam name="TImplementation">The type of the implementation to use.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="dependencies">An array of <see cref="Dependency"/> objects representing additional dependencies
    /// required by the service.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddScoped<TService, TImplementation>(this IServiceCollection services,
        params Dependency[] dependencies)
        where TService : class
        where TImplementation : class, TService
    {
        return services.AddScoped<TService, TImplementation>(sp => sp.CreateService<TImplementation>(dependencies));
    }

    /// <summary>
    /// Registers a singleton service of the type specified in <typeparamref name="T"/> with custom dependencies.
    /// A singleton service is created the first time it is requested, and subsequent requests use the same instance.
    /// </summary>
    /// <typeparam name="T">The type of the service to add.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="dependencies">An array of <see cref="Dependency"/> objects representing additional dependencies
    /// required by the service.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddSingleton<T>(this IServiceCollection services, params Dependency[] dependencies)
        where T : class
    {
        return services.AddSingleton(sp => sp.CreateService<T>(dependencies));
    }

    /// <summary>
    /// Registers a singleton service with the implementation type specified in <typeparamref name="TImplementation"/>
    /// and the service type specified in <typeparamref name="TService"/> with custom dependencies.
    /// </summary>
    /// <typeparam name="TService">The type of the service to add.</typeparam>
    /// <typeparam name="TImplementation">The type of the implementation to use.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="dependencies">An array of <see cref="Dependency"/> objects representing additional dependencies
    /// required by the service.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddSingleton<TService, TImplementation>(this IServiceCollection services,
        params Dependency[] dependencies)
        where TService : class
        where TImplementation : class, TService
    {
        return services.AddSingleton<TService, TImplementation>(sp => sp.CreateService<TImplementation>(dependencies));
    }


    /// <summary>
    /// Changes the lifetime of a registered service of type <typeparamref name="T"/>
    /// to the specified <paramref name="lifetime"/>.
    /// </summary>
    /// <typeparam name="T">The service type whose lifetime is to be changed.</typeparam>
    /// <param name="services">The service collection to operate on.</param>
    /// <param name="lifetime">The new <see cref="ServiceLifetime"/> to apply.</param>
    /// <returns>The modified <see cref="IServiceCollection"/> instance.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown if the service descriptor for <typeparamref name="T"/> has an unexpected format.
    /// </exception>
    /// <remarks>
    /// Useful when you need to override the lifetime of an existing registration (e.g., from Singleton to Scoped).
    /// </remarks>
    public static IServiceCollection ChangeLifetime<T>(this IServiceCollection services, ServiceLifetime lifetime)
    {
        var serviceType = typeof(T);

        var serviceDescriptor = services.FindRequired<T>() switch
        {
            { ImplementationFactory: { } factory }
                => ServiceDescriptor.Describe(serviceType, factory, lifetime),

            { ImplementationType: { } implementationType }
                => ServiceDescriptor.Describe(serviceType, implementationType, lifetime),

            _ => throw new InvalidOperationException($"The unexpected service descriptor for type {serviceType}"),
        };

        services.Replace(serviceDescriptor);

        return services;
    }

    /// <summary>
    /// Removes all registrations of type <typeparamref name="T"/> from the service collection.
    /// </summary>
    /// <typeparam name="T">The service type to remove.</typeparam>
    /// <param name="services">The service collection to operate on.</param>
    /// <returns>
    /// <c>true</c> if any descriptors were removed; otherwise, <c>false</c>.
    /// </returns>
    /// <remarks>
    /// Can be used to clean up pre-registered services before adding custom implementations.
    /// </remarks>
    public static ServiceDescriptor[] RemoveAll<T>(this IServiceCollection services)
    {
        var serviceDescriptors = services.FindAll<T>().ToArray();
        Array.ForEach(serviceDescriptors, serviceDescriptor => services.Remove(serviceDescriptor));
        return serviceDescriptors;
    }

    /// <summary>
    /// Finds the first registered service descriptor for type <typeparamref name="T"/>.
    /// Throws if no descriptor is found.
    /// </summary>
    /// <typeparam name="T">The service type to locate.</typeparam>
    /// <param name="services">The service collection to search.</param>
    /// <returns>The matching <see cref="ServiceDescriptor"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown if no descriptor is found for the specified type.
    /// </exception>
    public static ServiceDescriptor FindRequired<T>(this IServiceCollection services)
        => services.Find<T>() ?? throw new InvalidOperationException($"A service descriptor was not found for type {typeof(T)}");

    /// <summary>
    /// Finds the first registered service descriptor for type <typeparamref name="T"/>,
    /// or returns <c>null</c> if none exists.
    /// </summary>
    /// <typeparam name="T">The service type to locate.</typeparam>
    /// <param name="services">The service collection to search.</param>
    /// <returns>The matching <see cref="ServiceDescriptor"/>, or <c>null</c> if not found.</returns>
    public static ServiceDescriptor? Find<T>(this IServiceCollection services)
        => services.SingleOrDefault(s => s.ServiceType == typeof(T));

    /// <summary>
    /// Finds all registered service descriptors for type <typeparamref name="T"/>.
    /// </summary>
    /// <typeparam name="T">The service type to locate.</typeparam>
    /// <param name="services">The service collection to search.</param>
    /// <returns>An <see cref="IEnumerable{T}"/> of matching <see cref="ServiceDescriptor"/> instances.</returns>
    public static IEnumerable<ServiceDescriptor> FindAll<T>(this IServiceCollection services)
        => services.Where(s => s.ServiceType == typeof(T));
}
