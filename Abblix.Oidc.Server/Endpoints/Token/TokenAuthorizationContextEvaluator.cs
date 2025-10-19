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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Evaluates <see cref="AuthorizationContext"/> instances based on token requests.
/// </summary>
public class TokenAuthorizationContextEvaluator : ITokenAuthorizationContextEvaluator
{
    /// <summary>
    /// Evaluates and constructs a new <see cref="AuthorizationContext"/> by refining and reconciling the scopes
    /// and resources from the original authorization request based on the current token request.
    /// </summary>
    /// <param name="request">The valid token request that contains the original authorization grant and any additional
    /// token-specific requests.</param>
    /// <returns>An updated <see cref="AuthorizationContext"/> that reflects the actual scopes and resources that
    /// should be considered during the token issuance process.</returns>
    public AuthorizationContext EvaluateAuthorizationContext(ValidTokenRequest request)
    {
        var authContext = request.AuthorizedGrant.Context;

        // Determine the effective scopes for the token request.
        var scope = authContext.Scope;
        if (scope is { Length: > 0 } && request.Scope is { Length: > 0 })
        {
            scope = scope
                .Intersect(from sd in request.Scope select sd.Scope, StringComparer.Ordinal)
                .ToArray();
        }

        // Determine the effective resources for the token request.
        var resources = authContext.Resources;
        if (resources is { Length: > 0 } && request.Resources is { Length: > 0 })
        {
            resources = resources
                .Intersect(from rd in request.Resources select rd.Resource)
                .ToArray();
        }

        // Return a new authorization context updated with the determined scopes and resources.
        return authContext with
        {
            Scope = scope,
            Resources = resources,
        };
    }
}
