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

namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Defines an evaluator for determining the <see cref="AuthorizationContext"/> based on token requests.
/// </summary>
public interface ITokenAuthorizationContextEvaluator
{
    /// <summary>
    /// Evaluates and constructs a new <see cref="AuthorizationContext"/> by refining and reconciling the scopes and resources
    /// from the original authorization request based on the current token request.
    /// </summary>
    /// <param name="request">The valid token request that contains the original authorization grant and any additional
    /// token-specific requests.</param>
    /// <returns>An updated <see cref="AuthorizationContext"/> that reflects the actual scopes and resources that
    /// should be considered during the token issuance process.</returns>
    AuthorizationContext EvaluateAuthorizationContext(ValidTokenRequest request);
}
