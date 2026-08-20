// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Refuses to start an application that carries both OIDC transport adapters.
/// </summary>
/// <remarks>
/// Only one adapter may serve the OIDC endpoints; with both in place they claim the same paths and every OIDC
/// request fails with an <c>AmbiguousMatchException</c> that names the routing layer which noticed and neither
/// of the packages that caused it. Failing at startup with the package names is the difference between a
/// five-minute fix and an afternoon.
///
/// The mistake has two forms and each needs its own signal. A host may <b>call</b> both registrations, which
/// the service collection shows directly. Or it may merely <b>reference</b> the MVC package without calling
/// anything, which is already enough: <c>AddControllers()</c> discovers controller assemblies from the
/// dependency graph. Only the second form needs the assembly check, and only the Minimal API side can act on
/// it - the MVC adapter maps nothing of its own that the presence of the other package would collide with.
///
/// Lives in the shared assembly both adapter packages embed, so the two sides share one implementation and
/// supply only the message that speaks in their own terms.
/// </remarks>
internal static class TransportAdapterConflict
{
    /// <summary>The assembly the MVC transport adapter ships as.</summary>
    public const string MvcAdapterAssemblyName = "Abblix.Oidc.Server.Mvc";

    /// <summary>The assembly the Minimal API transport adapter ships as.</summary>
    public const string MinimalApiAdapterAssemblyName = "Abblix.Oidc.Server.MinimalApi";

    /// <summary>
    /// Throws when <paramref name="services"/> already carries a registration declared by the other adapter.
    /// </summary>
    /// <param name="services">The service collection being configured.</param>
    /// <param name="otherAdapterAssemblyName">The assembly whose contracts mark the other adapter.</param>
    /// <param name="message">What the host is told to do about it.</param>
    /// <exception cref="InvalidOperationException">The other adapter is already registered.</exception>
    /// <remarks>
    /// Cannot be a false positive: a host that registered both transports meant to serve the OIDC endpoints
    /// twice. Matched by assembly name rather than by type, so neither package takes a dependency on the one
    /// it refuses to sit beside.
    /// </remarks>
    public static void ThrowIfRegistered(
        IServiceCollection services, string otherAdapterAssemblyName, string message)
    {
        var registered = services.Any(descriptor => string.Equals(
            descriptor.ServiceType.Assembly.GetName().Name,
            otherAdapterAssemblyName,
            StringComparison.Ordinal));

        if (registered)
            throw new InvalidOperationException(message);
    }

    /// <summary>
    /// Throws when the other adapter's assembly is loaded into the application.
    /// </summary>
    /// <param name="otherAdapterAssemblyName">The assembly that marks the other adapter.</param>
    /// <param name="message">What the host is told to do about it.</param>
    /// <param name="loadedAssemblies">
    /// The assemblies to examine. Defaults to the ones loaded into the current application, and is supplied
    /// explicitly only by the tests, which cannot load the other adapter into their own process.
    /// </param>
    /// <exception cref="InvalidOperationException">The other adapter is present.</exception>
    /// <remarks>
    /// Loaded assemblies rather than declared references, which needs no dependency-model package and has a
    /// blind spot that is exactly the harmless case: the MVC adapter is loaded when <c>AddControllers()</c>
    /// scans for controllers, and a host that never calls <c>AddControllers()</c> can never map its
    /// controllers either.
    /// </remarks>
    public static void ThrowIfLoaded(
        string otherAdapterAssemblyName, string message, IEnumerable<Assembly>? loadedAssemblies = null)
    {
        var loaded = (loadedAssemblies ?? AppDomain.CurrentDomain.GetAssemblies()).Any(assembly =>
            string.Equals(assembly.GetName().Name, otherAdapterAssemblyName, StringComparison.Ordinal));

        if (loaded)
            throw new InvalidOperationException(message);
    }
}
