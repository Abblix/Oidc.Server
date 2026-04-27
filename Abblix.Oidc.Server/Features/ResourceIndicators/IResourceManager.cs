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
/// Looks up <see cref="ResourceDefinition"/> entries registered for the authorization server,
/// supporting validation of the <c>resource</c> parameter defined by RFC 8707 (Resource Indicators
/// for OAuth 2.0) at the authorization, token, and PAR endpoints.
/// </summary>
/// <remarks>
/// Acts as the registry that decides whether a requested resource URI corresponds to an audience
/// the server is willing to mint tokens for, and which scopes that resource accepts.
/// </remarks>
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
