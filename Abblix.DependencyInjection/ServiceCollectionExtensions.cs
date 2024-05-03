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
    /// Registers an alias for a service type to a specific implementation.
    /// </summary>
    /// <typeparam name="TService">The service type to be aliased.</typeparam>
    /// <typeparam name="TImplementation">The implementation type to use for the alias.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddAlias<TService, TImplementation>(this IServiceCollection services)
        where TImplementation : class, TService
        where TService : class
    {
        var descriptor = new ServiceDescriptor(
            typeof(TService),
            sp => sp.GetRequiredService<TImplementation>(),
            services.GetDescriptor<TImplementation>().Lifetime);

        services.Add(descriptor);
        return services;
    }

    /// <summary>
    /// Composes a service type with multiple implementations into a single composite service.
    /// </summary>
    /// <typeparam name="TInterface">The interface type to be composed.</typeparam>
    /// <typeparam name="TComposite">The composite implementation type.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="dependencies">The dependencies required by the composite service.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection Compose<TInterface, TComposite>(
        this IServiceCollection services,
        params Dependency[] dependencies)
        where TInterface : class where TComposite : class, TInterface
    {
        var parameterType = typeof(TComposite)
            .GetConstructors(BindingFlags.Instance | BindingFlags.Public)
            .SelectMany(constructor => constructor.GetParameters(), (_, parameterInfo) => parameterInfo.ParameterType)
            .FirstOrDefault(type => type.IsAssignableFrom(typeof(TInterface[])));

        if (parameterType == null)
            throw new InvalidOperationException(
                $"The type {typeof(TComposite).FullName} has no public constructor that accepts {typeof(TInterface).FullName}[]");

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
        services.Add(compositeDescriptor);

        return services;
    }

    /// <summary>
    /// Decorates a registered service with a decorator implementation.
    /// </summary>
    /// <typeparam name="TInterface">The service type to be decorated.</typeparam>
    /// <typeparam name="TDecorator">The decorator implementation type.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="dependencies">The dependencies required by the decorator.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection Decorate<TInterface, TDecorator>(
        this IServiceCollection services,
        params Dependency[] dependencies)
        where TInterface : class where TDecorator : class, TInterface
    {
        var serviceDescriptor = services.GetDescriptor<TInterface>();

        var decoratorDescriptor = ServiceDescriptor.Describe(
            typeof(TInterface),
            serviceProvider =>
            {
                var instance = Dependency.Override((TInterface)serviceProvider.CreateService(serviceDescriptor));
                return serviceProvider.CreateService<TDecorator>(dependencies.Append(instance));
            },
            serviceDescriptor.Lifetime);

        return services.Replace(decoratorDescriptor);
    }

    private static T[] Append<T>(this T[] source, T element)
    {
        switch (source)
        {
            case { Length: > 0 }:
                Array.Resize(ref source, source.Length + 1);
                source[^1] = element;
                return source;

            default:
                return new[] { element };
        }
    }

    private static ServiceDescriptor GetDescriptor<TInterface>(this IServiceCollection services)
        where TInterface : class
    {
        return services.SingleOrDefault(s => s.ServiceType == typeof(TInterface))
               ?? throw new InvalidOperationException($"{typeof(TInterface).Name} is not registered");
    }

    private static object CreateService(this IServiceProvider serviceProvider, ServiceDescriptor descriptor)
    {
        return descriptor switch
        {
            { ImplementationInstance: { } instance } => instance,
            { ImplementationFactory: { } factory } => factory(serviceProvider),
            { ImplementationType: { } type } => ActivatorUtilities.GetServiceOrCreateInstance(serviceProvider, type),
            _ => throw new InvalidOperationException($"Unable to create instance of {descriptor.ServiceType.FullName}")
        };
    }

    public static T CreateService<T>(this IServiceProvider serviceProvider, params Dependency[] dependencies)
    {
        return (T)serviceProvider.CreateService(typeof(T), dependencies);
    }

    public static object CreateService(this IServiceProvider serviceProvider,
        Type type, params Dependency[] dependencies)
    {
        var factory = ActivatorUtilities.CreateFactory(type, Array.ConvertAll(dependencies, d => d.Type));
        return factory(serviceProvider, Array.ConvertAll(dependencies, d => d.Factory(serviceProvider)));
    }

    /// <summary>
    /// Registers a transient service with custom dependencies.
    /// </summary>
    /// <typeparam name="T">The service type to register.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="dependencies">The dependencies required by the service.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddTransient<T>(this IServiceCollection services, params Dependency[] dependencies)
        where T : class
    {
        return services.AddTransient(sp => sp.CreateService<T>(dependencies));
    }

    /// <summary>
    /// Registers a transient service with custom dependencies.
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
    /// <param name="dependencies">An array of <see cref="Dependency"/> objects representing additional dependencies required by the service.</param>
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
    /// <param name="dependencies">An array of <see cref="Dependency"/> objects representing additional dependencies required by the service.</param>
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
    /// <param name="dependencies">An array of <see cref="Dependency"/> objects representing additional dependencies required by the service.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddSingleton<T>(this IServiceCollection services, params Dependency[] dependencies)
        where T : class
    {
        return services.AddSingleton(sp => sp.CreateService<T>(dependencies));
    }

    /// <summary>
    /// Registers a singleton service of the type specified in <typeparamref name="TService"/> with custom dependencies.
    /// A singleton service is created the first time it is requested, and subsequent requests use the same instance.
    /// </summary>
    /// <typeparam name="TService">The type of the service to add.</typeparam>
    /// <typeparam name="TImplementation">The type of the implementation to use.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <param name="dependencies">An array of <see cref="Dependency"/> objects representing additional dependencies required by the service.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>

    public static IServiceCollection AddSingleton<TService, TImplementation>(this IServiceCollection services,
        params Dependency[] dependencies)
        where TService : class
        where TImplementation : class, TService
    {
        return services.AddSingleton<TService, TImplementation>(sp => sp.CreateService<TImplementation>(dependencies));
    }
}