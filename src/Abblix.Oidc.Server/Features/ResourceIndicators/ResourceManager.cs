// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.ResourceIndicators;

/// <summary>
/// In-memory <see cref="IResourceManager"/> backed by <see cref="TenantDefinition.Resources"/>, one dictionary for each tenant. Indexes
/// the configured <see cref="ResourceDefinition"/> entries by their absolute URI for O(1) lookup
/// during RFC 8707 resource indicator validation.
/// </summary>
/// <remarks>
/// The dictionary of each tenant is built the first time that tenant looks a resource up, and again once
/// its resource definitions change, as after a change of its definition.
/// </remarks>
/// <param name="resources">The dictionary of each tenant.</param>
public class ResourceManager(IIssuerLocal<Dictionary<Uri, ResourceDefinition>> resources) : IResourceManager
{
    private Dictionary<Uri, ResourceDefinition> ResourcesOf(TenantDefinition tenant)
    {
        var definitions = tenant.Resources;
        return resources.GetOrCreate(tenant, definitions, () => InitializeResources(definitions));
    }

    private static Dictionary<Uri, ResourceDefinition> InitializeResources(ResourceDefinition[]? definitions)
    {
        var resources = new Dictionary<Uri, ResourceDefinition>();
        if (definitions == null)
            return resources;

        foreach (var resource in definitions)
        {
            // A non-absolute resource URI can never match a request (requests are rejected unless
            // absolute per RFC 8707 Section 2), so it would sit as a silent dead entry. Fail fast
            // with a clear message instead.
            if (!resource.Resource.IsAbsoluteUri)
                throw new ArgumentException(
                    $"The configured resource '{resource.Resource}' must be an absolute URI (RFC 8707 Section 2).",
                    nameof(definitions));

            if (!resources.TryAdd(resource.Resource, resource))
                throw new ArgumentException(
                    $"Duplicate resource definition for '{resource.Resource}'. Each configured resource URI must be unique.",
                    nameof(definitions));
        }

        return resources;
    }

    /// <summary>
    /// Attempts to retrieve the resource definition associated with the specified URI.
    /// </summary>
    /// <param name="tenant">The tenant whose resources are searched.</param>
    /// <param name="resource">The URI identifying the resource for which the definition is requested.</param>
    /// <param name="definition">When this method returns, contains the resource definition associated with
    /// the specified URI, if the resource is found; otherwise, null. This parameter is passed uninitialized.</param>
    /// <returns><c>true</c> if the resource definition is found; otherwise, <c>false</c>.</returns>
    public bool TryGet(TenantDefinition tenant, Uri resource, [MaybeNullWhen(false)] out ResourceDefinition definition)
        => ResourcesOf(tenant).TryGetValue(resource, out definition);
}
