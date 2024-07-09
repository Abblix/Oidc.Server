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
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.ResourceIndicators;

/// <summary>
/// Provides an interface for managing and retrieving resource definitions. This interface is essential for
/// ensuring that requests for resources are validated against registered and recognized definitions, supporting
/// the enforcement of policies related to resource access and permissions.
/// </summary>
public interface IResourceManager
{
    /// <summary>
    /// Attempts to retrieve the resource definition associated with the specified URI.
    /// </summary>
    /// <param name="resource">The URI identifying the resource for which the definition is requested.</param>
    /// <param name="definition">When this method returns, contains the resource definition associated with
    /// the specified URI, if the resource is found; otherwise, null. This parameter is passed uninitialized.</param>
    /// <returns><c>true</c> if the resource definition is found; otherwise, <c>false</c>.</returns>
    bool TryGet(Uri resource, [MaybeNullWhen(false)] out ResourceDefinition definition);
}
