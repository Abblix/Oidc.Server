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

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;

/// <summary>
/// Provides validation for pushed authorization requests in an OAuth 2.0 context, ensuring they adhere
/// to protocol specifications.
/// This interface evaluates the conformity of authorization requests with expected parameters and
/// limitations before their acceptance for processing.
/// </summary>
public interface IPushedAuthorizationRequestValidator
{
    /// <summary>
    /// Asynchronously validates a pushed authorization request against OAuth 2.0 specifications.
    /// This method ensures the request meets all necessary criteria and constraints defined for secure processing.
    /// </summary>
    /// <param name="authorizationRequest">The authorization request to be validated.</param>
    /// <param name="clientRequest">Additional client request information for contextual validation.</param>
    /// <returns>A task that upon completion provides a validation result, indicating either success and validity
    /// of the request or the presence of errors.</returns>
    Task<AuthorizationRequestValidationResult> ValidateAsync(
        AuthorizationRequest authorizationRequest,
        ClientRequest clientRequest);
}
