// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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