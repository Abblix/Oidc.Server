// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.AspNetCore.Formatters;

/// <summary>
/// Refuses a host's response formatter registered under a shared formatter contract closed over a result type the
/// adapter being added never resolves.
/// </summary>
/// <remarks>
/// Each adapter resolves every formatter closed over its own result type only, so such a registration compiles,
/// is never used, and leaves the endpoint answered by the library's default with nothing saying so. Only what is
/// registered before the adapter is seen: a registration made after it is not examined.
/// </remarks>
internal static class ResponseFormatterClosure
{
    /// <summary>
    /// Throws when <paramref name="services"/> carries a shared formatter contract closed over a result type other
    /// than <paramref name="adapterResultType"/>.
    /// </summary>
    /// <param name="services">The service collection the adapter is being added to.</param>
    /// <param name="adapterResultType">The result type the adapter resolves its formatters by.</param>
    /// <exception cref="InvalidOperationException">A formatter is closed over another result type.</exception>
    public static void ThrowIfClosedOverAnotherResult(IServiceCollection services, Type adapterResultType)
    {
        var contractNamespace = typeof(ITokenResponseFormatter<>).Namespace;
        var contractAssembly = typeof(ITokenResponseFormatter<>).Assembly;

        // An open generic registration is closed by the container over whatever type is asked for, the adapter's
        // own included, so it is always used and is never refused.
        var closedContracts = services
            .Select(descriptor => descriptor.ServiceType)
            .Where(serviceType => serviceType is { IsInterface: true, IsGenericType: true, IsGenericTypeDefinition: false });

        foreach (var serviceType in closedContracts)
        {
            var contract = serviceType.GetGenericTypeDefinition();
            if (contract.Assembly != contractAssembly || contract.Namespace != contractNamespace)
                continue;

            if (serviceType.GetGenericArguments()[0] == adapterResultType)
                continue;

            throw new InvalidOperationException(
                $"A response formatter is registered as {NameOf(serviceType)}, but this OIDC transport adapter " +
                $"resolves {NameOf(contract.MakeGenericType(adapterResultType))}, so the registered formatter " +
                "would never be used. Register it under the contract closed over the adapter's result type.");
        }
    }

    private static string NameOf(Type type)
    {
        if (!type.IsGenericType)
            return type.FullName ?? type.Name;

        var name = type.GetGenericTypeDefinition().FullName ?? type.Name;
        return $"{name[..name.IndexOf('`')]}<{string.Join(", ", type.GetGenericArguments().Select(NameOf))}>";
    }
}
