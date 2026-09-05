// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.UserInfo;

/// <summary>
/// Defines a service responsible for determining the claims associated with specific OAuth 2.0 and OpenID Connect scopes.
/// This interface facilitates the mapping of requested scopes to their corresponding claims, enabling effective claims
/// management based on the authorization policies and client request parameters.
/// </summary>
public interface IScopeClaimsProvider
{
    /// <summary>
    /// Retrieves the set of claim names associated with the requested scopes and any additional claim details.
    /// This method allows for dynamic claim resolution based on the authorization request, supporting customization
    /// of claims returned in tokens or user info responses.
    /// </summary>
    /// <param name="scopes">An enumerable of strings representing the requested scopes. Each scope can be associated
    /// with one or multiple claims as defined by the implementation.</param>
    /// <param name="requestedClaims">An optional collection of additional claims requested, which may not necessarily
    /// be tied to specific scopes but are required by the client.</param>
    /// <returns>An IEnumerable of strings, each representing a claim name that should be included based on the
    /// requested scopes and additional claims.</returns>
    IEnumerable<string> GetRequestedClaims(IEnumerable<string> scopes, IEnumerable<string>? requestedClaims);

    /// <summary>
    /// Provides a collection of all the scopes that are recognized and supported by this provider.
    /// This property can be used to validate scope requests or to generate metadata for discovery documents.
    /// </summary>
    IEnumerable<string> ScopesSupported { get; }

    /// <summary>
    /// Provides a collection of all the claims that this provider can handle.
    /// These claims represent the total set of data points that can be requested through various scopes
    /// and are used for constructing tokens and user information responses.
    /// </summary>
    IEnumerable<string> ClaimsSupported { get; }
}
