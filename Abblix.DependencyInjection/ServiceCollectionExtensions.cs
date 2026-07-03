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
    /// Adds <typeparamref name="TService"/> to an enumerable strategy set as a SHARED-instance
    /// alias for the existing <typeparamref name="TImplementation"/> registration. Sister of
    /// <see cref="AddAlias{TService,TImplementation}"/>: same semantic of «route this service
    /// to that already-registered impl», but adds via <c>TryAddEnumerable</c> (so repeated
    /// calls dedupe on <c>(ServiceType, ImplementationType)</c>) and always uses a typed
    /// factory delegate that resolves through the source registration — guaranteeing the
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
    /// (<c>ImplementationType == TImpl</c>) — without this priority a second alias-helper
    /// call would pick the previous alias as «source», capture the wrong ServiceType, and
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
    /// sees <c>ImplementationType = object</c>, hits the «implementationType == typeof(object)»
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
    /// <c>ImplementationType</c>, an <c>ImplementationInstance</c>, or a typed factory
    /// <c>Func&lt;IServiceProvider, TImpl&gt;</c> (.NET 10 generic AddSingleton uses the last shape,
    /// so the property alone returns null for those registrations).
    /// </summary>
    private static Type? ResolveImplementationType(ServiceDescriptor descriptor)
    {
        if (descriptor.ImplementationType != null)
            return descriptor.ImplementationType;

        if (descriptor.ImplementationInstance != null)
            return descriptor.ImplementationInstance.GetType();

        var factory = descriptor.ImplementationFactory;
        if (factory != null)
        {
            var args = factory.GetType().GetGenericArguments();
            if (args.Length == 2)
                return args[1];
        }

        return null;
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
        // Find the most recent keyed registration of TSource
        var source = services.LastOrDefault(s =>
            (s.ServiceType == typeof(TSource) || s.ImplementationType == typeof(TSource)) &&
            Equals(s.ServiceKey, sourceKey))
            ?? throw new InvalidOperationException(
                $"No registration found for {typeof(TSource).Name} with key '{sourceKey}'. " +
                $"Register it first before creating an alias.");

        // Clone the descriptor with TService as the new ServiceType and serviceKey
        services.Add(source.CloneKeyed(typeof(TService), serviceKey));

        return services;
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
    /// All existing registrations are collected and provided to the composite service.
    /// The composite service uses the shortest lifetime among the existing registrations.
    /// </remarks>
    public static IServiceCollection Compose<TInterface, TComposite>(
        this IServiceCollection services,
        params Dependency[] dependencies)
        where TInterface : class where TComposite : class, TInterface
    {
        var parameterType = typeof(TComposite)
            .GetConstructors(BindingFlags.Instance | BindingFlags.Public)
            .SelectMany(constructor => constructor.GetParameters(), (_, parameterInfo) => parameterInfo.ParameterType)
            .FirstOrDefault(type => type.IsAssignableFrom(typeof(TInterface[])))
            ?? throw new InvalidOperationException(
                $"The type {typeof(TComposite).FullName} has no public constructor that accepts {typeof(TInterface).FullName}[]");

        // Fail loud when this family has already been composed. A previous Compose registered TComposite as a
        // concrete descriptor and replaced the individual TInterface leaves with one alias to it. A second run
        // re-adds the leaves (the originals were physically removed, so TryAddEnumerable no longer dedupes them)
        // and rebuilds the composite over a snapshot that already holds that alias, so the new composite would
        // resolve one of its own children back to itself — a self-referential singleton that deadlocks on first
        // resolve. This happens when an opt-in feature is applied twice (e.g. two registration modules both call
        // AddBackChannelAuthentication or AddDeviceAuthorization) or a public compose-family method is called
        // before AddOidcCore, which composes it again. Register every TInterface implementation before
        // AddOidcCore/AddOidcServices, which composes each family exactly once.
        if (services.Any(descriptor => descriptor.ServiceType == typeof(TComposite)))
        {
            throw new InvalidOperationException(
                $"{typeof(TComposite).Name} is already registered, so the {typeof(TInterface).Name} pipeline has " +
                "already been composed. Composing it a second time would build a self-referential composite that " +
                $"deadlocks on the first resolve. Register all {typeof(TInterface).Name} implementations before " +
                "AddOidcCore/AddOidcServices, which composes each family once; do not call the same opt-in feature " +
                "method (or a compose-family method) twice.");
        }

        var serviceDescriptors = services
            .Where(descriptor => descriptor.ServiceType == typeof(TInterface))
            .ToArray();

        if (serviceDescriptors.Length <= 1)
            return services;

        // choose the shortest lifetime among existing service registrations
        var lifetime = serviceDescriptors.Max(descriptor => descriptor.Lifetime);

        var compositeDescriptor = ServiceDescriptor.Describe(
            typeof(TInterface),
            serviceProvider =>
            {
                var serviceInstances = Array.ConvertAll(
                    serviceDescriptors,
                    serviceDescriptor => (TInterface)serviceProvider.CreateService(serviceDescriptor));

                var serviceDependencies = Dependency.Override(parameterType, serviceInstances);
                return serviceProvider.CreateService<TComposite>(dependencies.Append(serviceDependencies));
            },
            lifetime);

        services.RemoveAll<TInterface>();

        // Register the composite type itself so it can be aliased
        var compositeTypeDescriptor = ServiceDescriptor.Describe(
            typeof(TComposite),
            compositeDescriptor.ImplementationFactory!,
            lifetime);
        services.Add(compositeTypeDescriptor);

        // Register the interface to resolve the composite type
        services.AddAlias<TInterface, TComposite>();

        // Record the composed family so a downstream integrity check can detect a service registered for TInterface
        // after composition, which would shadow this composite on the last-wins singular resolve.
        services.RecordComposedFamily(typeof(TInterface), typeof(TComposite));

        return services;
    }

    private static void RecordComposedFamily(this IServiceCollection services, Type serviceType, Type compositeType)
    {
        if (services.FirstOrDefault(descriptor => descriptor.ServiceType == typeof(ComposedFamilyRegistry))
                ?.ImplementationInstance is not ComposedFamilyRegistry registry)
        {
            registry = new ComposedFamilyRegistry();
            services.AddSingleton(registry);
        }

        registry.Record(serviceType, compositeType);
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
