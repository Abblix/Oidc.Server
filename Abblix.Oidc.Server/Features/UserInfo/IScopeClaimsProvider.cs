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
