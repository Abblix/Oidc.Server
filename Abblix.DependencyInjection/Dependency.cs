// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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