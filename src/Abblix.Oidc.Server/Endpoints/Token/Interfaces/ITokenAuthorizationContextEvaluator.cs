// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
