// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ResourceIndicators;

/// <summary>
/// In-memory <see cref="IResourceManager"/> backed by <see cref="OidcOptions.Resources"/>. Indexes
/// the configured <see cref="ResourceDefinition"/> entries by their absolute URI for O(1) lookup
/// during RFC 8707 resource indicator validation.
/// </summary>
/// <remarks>
/// The dictionary is built once at construction time from the snapshot of options; subsequent
/// changes to the options instance are not reflected.
/// </remarks>
/// <param name="options">The OIDC options containing resource definitions to be registered.</param>
public class ResourceManager(IOptions<OidcOptions> options) : IResourceManager
{
    private readonly Dictionary<Uri, ResourceDefinition> _resources = InitializeResources(options);

    private static Dictionary<Uri, ResourceDefinition> InitializeResources(IOptions<OidcOptions> options)
    {
        var resources = new Dictionary<Uri, ResourceDefinition>();
        if (options.Value.Resources == null)
            return resources;

        foreach (var resource in options.Value.Resources)
        {
            // A non-absolute resource URI can never match a request (requests are rejected unless
            // absolute per RFC 8707 Section 2), so it would sit as a silent dead entry. Fail fast
            // with a clear message instead.
            if (!resource.Resource.IsAbsoluteUri)
                throw new ArgumentException(
                    $"The configured resource '{resource.Resource}' must be an absolute URI (RFC 8707 Section 2).",
                    nameof(options));

            if (!resources.TryAdd(resource.Resource, resource))
                throw new ArgumentException(
                    $"Duplicate resource definition for '{resource.Resource}'. Each configured resource URI must be unique.",
                    nameof(options));
        }

        return resources;
    }

    /// <summary>
    /// Attempts to retrieve the resource definition associated with the specified URI.
    /// </summary>
    /// <param name="resource">The URI identifying the resource for which the definition is requested.</param>
    /// <param name="definition">When this method returns, contains the resource definition associated with
    /// the specified URI, if the resource is found; otherwise, null. This parameter is passed uninitialized.</param>
    /// <returns><c>true</c> if the resource definition is found; otherwise, <c>false</c>.</returns>
    public bool TryGet(Uri resource, [MaybeNullWhen(false)] out ResourceDefinition definition)
        => _resources.TryGetValue(resource, out definition);
}
