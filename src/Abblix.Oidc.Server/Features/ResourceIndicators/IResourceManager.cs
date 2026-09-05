// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
