// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.ResourceIndicators;

/// <summary>
/// Provides extension methods for resource validation, leveraging a resource manager to ensure the validity and
/// permissibility of requested resources.
/// </summary>
public static class ResourceManagerExtensions
{
    /// <summary>
    /// Validates requested resources against registered resource definitions to confirm their validity and
    /// authorization.
    /// This method ensures that resources and the requested scopes within those resources are registered and allowed.
    /// </summary>
    /// <param name="resourceManager">The resource manager that maintains the definitions of resources.</param>
    /// <param name="resources">A collection of URIs representing the resources being requested.</param>
    /// <param name="scopes">A collection of scope identifiers associated with the request.</param>
    /// <param name="resourceDefinitions">Outputs an array of <see cref="ResourceDefinition"/> objects if
    /// the validation is successful, otherwise null.</param>
    /// <param name="errorDescription">Outputs a string describing the reason for validation failure,
    /// otherwise null if the validation is successful.</param>
    /// <returns>True if all requested resources and their corresponding scopes are valid and permissible,
    /// false otherwise.</returns>
    public static bool Validate(
        this IResourceManager resourceManager,
        IEnumerable<Uri> resources,
        IEnumerable<string> scopes,
        [MaybeNullWhen(false)] out ResourceDefinition[] resourceDefinitions,
        [MaybeNullWhen(true)] out string errorDescription)
    {
        resourceDefinitions = null;
        errorDescription = null;

        var resourceList = new List<ResourceDefinition>();
        var scopeSet = scopes.ToHashSet(StringComparer.Ordinal);

        foreach (var resource in resources)
        {
            if (!resource.IsAbsoluteUri)
            {
                errorDescription = "The resource must be absolute URI";
                return false;
            }

            if (resource.Fragment.HasValue())
            {
                errorDescription = "The requested resource must not contain fragment part";
                return false;
            }

            if (!resourceManager.TryGet(resource, out var definition))
            {
                errorDescription = "The requested resource is unknown";
                return false;
            }

            // Filter the scopes of the resource to include only those that are requested
            var requestedScopes = definition.Scopes
                .Where(def => scopeSet.Contains(def.Scope))
                .ToArray();

            resourceList.Add(definition with { Scopes = requestedScopes });
        }

        resourceDefinitions = resourceList.ToArray();
        return true;
    }
}
