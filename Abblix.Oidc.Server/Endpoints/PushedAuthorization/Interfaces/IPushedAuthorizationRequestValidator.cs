// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
