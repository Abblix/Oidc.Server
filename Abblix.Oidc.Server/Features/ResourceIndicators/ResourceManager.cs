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

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ResourceIndicators;

/// <summary>
/// Manages resource definitions, ensuring they are registered and retrievable based on their URIs.
/// </summary>
/// <param name="options">The OIDC options containing resource definitions to be registered.</param>
public class ResourceManager(IOptions<OidcOptions> options) : IResourceManager
{
    private readonly Dictionary<Uri, ResourceDefinition> _resources = InitializeResources(options);

    private static Dictionary<Uri, ResourceDefinition> InitializeResources(IOptions<OidcOptions> options)
    {
        var resources = new Dictionary<Uri, ResourceDefinition>();
        if (options.Value.Resources != null)
            Array.ForEach(options.Value.Resources, resource => resources.Add(resource.Resource, resource));
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
