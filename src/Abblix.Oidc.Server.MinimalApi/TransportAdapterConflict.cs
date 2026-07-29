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

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Refuses to start an application that carries both OIDC transport adapters.
/// </summary>
/// <remarks>
/// Only one adapter may serve the OIDC endpoints. Merely referencing the MVC package is enough to bring its
/// controllers in - <c>AddControllers()</c> discovers controller assemblies from the dependency graph, with or
/// without a call to <c>AddOidcServices()</c> - so both transports end up claiming <c>/connect/*</c> and
/// <c>/.well-known/*</c>. What the host then sees is an <c>AmbiguousMatchException</c> on every OIDC request,
/// which names the routing layer that noticed and says nothing about the two packages that caused it. Failing
/// at startup with the package names is the difference between a five-minute fix and an afternoon.
/// </remarks>
internal static class TransportAdapterConflict
{
    /// <summary>The assembly the MVC transport adapter ships as.</summary>
    private const string MvcAdapterAssemblyName = "Abblix.Oidc.Server.Mvc";

    /// <summary>
    /// Throws when the MVC transport adapter is present alongside this one.
    /// </summary>
    /// <param name="loadedAssemblies">
    /// The assemblies to examine. Defaults to the ones loaded into the current application, and is supplied
    /// explicitly only by the tests, which cannot load the other adapter into their own process.
    /// </param>
    /// <exception cref="InvalidOperationException">Both adapters are present.</exception>
    public static void ThrowIfAdaptersPresent(IEnumerable<Assembly>? loadedAssemblies = null)
    {
        // Loaded assemblies rather than declared references, which needs no dependency-model package and has a
        // blind spot that is exactly the harmless case: the MVC adapter is loaded when AddControllers() scans
        // for controllers, and a host that never calls AddControllers() can never map its controllers either.
        if (!IsMvcAdapterLoaded(loadedAssemblies ?? AppDomain.CurrentDomain.GetAssemblies()))
            return;

        throw new InvalidOperationException(
            "Both OIDC transport adapters are present in this application: MapOidcEndpoints() maps the " +
            "Minimal API endpoints, and the MVC adapter (Abblix.OIDC.Server.MVC) is loaded as well. Only one " +
            "of them may serve the OIDC endpoints. Referencing the MVC package is enough to bring its " +
            "controllers in - AddControllers() finds them in the dependency graph whether or not " +
            "AddOidcServices() was ever called - so both transports would claim /connect/* and " +
            "/.well-known/*, and every OIDC request would fail with AmbiguousMatchException. " +
            "To stay on Minimal API, remove the Abblix.OIDC.Server.MVC package reference together with any " +
            "AddOidcServices() or AddOidcMvc() call. To stay on MVC, remove the " +
            "Abblix.OIDC.Server.MinimalApi package reference together with this MapOidcEndpoints() call.");
    }

    /// <summary>
    /// Reports whether the MVC transport adapter is among the given assemblies. Separated from the ambient
    /// <see cref="AppDomain"/> so the decision can be exercised without loading the other adapter into the
    /// test process, which would then trip every other test that maps endpoints.
    /// </summary>
    private static bool IsMvcAdapterLoaded(IEnumerable<Assembly> assemblies)
        => assemblies.Any(assembly =>
            string.Equals(assembly.GetName().Name, MvcAdapterAssemblyName, StringComparison.Ordinal));
}
