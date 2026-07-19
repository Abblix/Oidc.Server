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

using Microsoft.Extensions.DependencyInjection;



namespace Abblix.DependencyInjection;

/// <summary>
/// Represents a dependency that can be overridden in a service provider.
/// This struct provides various static methods to create dependency overrides based on type, instance, or factory functions.
/// </summary>
public readonly struct Dependency
{
    /// <summary>
    /// Creates a dependency override where a specified actual type fulfills the contract of a declared type.
    /// </summary>
    /// <typeparam name="TDeclared">The declared type of the dependency.</typeparam>
    /// <typeparam name="TActual">The actual type to be used as the implementation.</typeparam>
    /// <returns>A new <see cref="Dependency"/> instance.</returns>
    public static Dependency Override<TDeclared, TActual>() where TActual : TDeclared
        => new(typeof(TDeclared), sp => ActivatorUtilities.GetServiceOrCreateInstance<TActual>(sp)!);

    /// <summary>
    /// Creates a dependency override with a specific instance for the declared type.
    /// </summary>
    /// <typeparam name="TDeclared">The declared type of the dependency.</typeparam>
    /// <param name="instance">The instance to use for the dependency.</param>
    /// <returns>A new <see cref="Dependency"/> instance.</returns>
    public static Dependency Override<TDeclared>(TDeclared instance)
        => new(typeof(TDeclared), _ => instance!);

    /// <summary>
    /// Creates a dependency override using a factory function for the declared type.
    /// </summary>
    /// <typeparam name="TDeclared">The declared type of the dependency.</typeparam>
    /// <param name="factory">The factory function to create the dependency instance.</param>
    /// <returns>A new <see cref="Dependency"/> instance.</returns>
    public static Dependency Override<TDeclared>(Func<IServiceProvider, TDeclared> factory)
        => new(typeof(TDeclared), sp => factory(sp)!);

    /// <summary>
    /// Creates a dependency override where a specified actual type fulfills the contract of a declared type.
    /// </summary>
    /// <param name="declared">The declared type of the dependency.</param>
    /// <param name="actual">The actual type to be used as the implementation.</param>
    /// <returns>A new <see cref="Dependency"/> instance.</returns>
    public static Dependency Override(Type declared, Type actual)
        => new(declared, sp => ActivatorUtilities.GetServiceOrCreateInstance(sp, actual));

    /// <summary>
    /// Creates a dependency override with a specific instance for the declared type.
    /// </summary>
    /// <param name="declared">The declared type of the dependency.</param>
    /// <param name="instance">The instance to use for the dependency.</param>
    /// <returns>A new <see cref="Dependency"/> instance.</returns>
    public static Dependency Override(Type declared, object instance)
        => new(declared, _ => instance);

    /// <summary>
    /// Creates a dependency override using a factory function for the declared type.
    /// </summary>
    /// <param name="declared">The declared type of the dependency.</param>
    /// <param name="factory">The factory function to create the dependency instance.</param>
    /// <returns>A new <see cref="Dependency"/> instance.</returns>
    public static Dependency Override(Type declared, Func<IServiceProvider, object> factory)
        => new(declared, factory);

    private Dependency(Type type, Func<IServiceProvider, object> factory)
    {
        Type = type;
        Factory = factory;
    }

    /// <summary>
    /// The declared type of the dependency.
    /// </summary>
    internal Type Type { get; }

    /// <summary>
    /// The factory function used to create the dependency instance.
    /// </summary>
    internal Func<IServiceProvider, object> Factory { get; }
}