// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.Issuer;

namespace Abblix.Oidc.Server.Features.ResourceIndicators;

/// <summary>
/// Infers the resource a request is meant for from the scopes it asks for, where the issuer serving it says so in
/// <see cref="IIssuerSettings.InferResourceFromScope"/>.
/// </summary>
/// <remarks>
/// RFC 9068 section 3: "If a "scope" parameter is present in the request, the authorization server SHOULD use it to
/// infer the value of the default resource indicator to be used in the "aud" claim", and "If the values in the
/// "scope" parameter refer to different default resource indicator values, the authorization server SHOULD reject
/// the request with "invalid_scope"". A scope refers to the registered resources whose definitions declare it.
/// </remarks>
/// <param name="settings">The settings of the issuer serving the request, holding its resources.</param>
public sealed class ResourceInference(IIssuerSettings settings)
{
    /// <summary>
    /// The resource the requested scopes refer to.
    /// </summary>
    /// <param name="scopes">The scopes the request asks for.</param>
    /// <param name="resource">The one resource the scopes refer to; null when inference is off for the issuer or
    /// no requested scope refers to a resource.</param>
    /// <param name="errorDescription">Why the request is refused, when the scopes refer to more than one resource.
    /// </param>
    /// <returns>False when the scopes refer to more than one resource, so no single one can be inferred.</returns>
    public bool TryInfer(
        IEnumerable<string> scopes,
        out Uri? resource,
        [MaybeNullWhen(true)] out string errorDescription)
    {
        resource = null;
        errorDescription = null;

        if (!settings.InferResourceFromScope || settings.Resources is not { Length: > 0 } definitions)
            return true;

        var requested = scopes.ToHashSet(StringComparer.Ordinal);
        var referred = definitions
            .Where(definition => definition.Scopes.Any(scope => requested.Contains(scope.Scope)))
            .Select(definition => definition.Resource)
            .ToArray();

        if (referred.Length > 1)
        {
            errorDescription = "The requested scopes refer to more than one resource, so the request has to name " +
                               "the one it is for in the resource parameter";
            return false;
        }

        resource = referred.SingleOrDefault();
        return true;
    }
}
