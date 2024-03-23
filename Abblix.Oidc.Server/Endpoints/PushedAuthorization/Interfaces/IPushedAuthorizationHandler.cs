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
/// Defines the contract for handling Pushed Authorization Requests (PAR) as specified in OAuth 2.0 and OpenID Connect.
/// Ensures that implementations can validate and process these requests in a secure and compliant manner.
/// </summary>
public interface IPushedAuthorizationHandler
{
    /// <summary>
    /// Asynchronously handles and processes a Pushed Authorization Request, ensuring it complies with OAuth 2.0
    /// and OpenID Connect specifications.
    /// </summary>
    /// <param name="authorizationRequest">An instance of <see cref="AuthorizationRequest"/> representing the details
    /// of the authorization request submitted by the client.</param>
    /// <param name="clientRequest">An instance of <see cref="ClientRequest"/> providing additional information about
    /// the client making the request, used for contextual validation.</param>
    /// <returns>
    /// A <see cref="Task"/> that resolves to an <see cref="AuthorizationResponse"/>, indicating the outcome of the
    /// request processing. The response can be a successful authorization or an error response if the request
    /// fails validation or processing.
    /// </returns>
    /// <remarks>
    /// This method is central to the PAR mechanism, enabling clients to pre-register authorization requests.
    /// It validates the request against system policies and, if valid, processes it to generate a unique request URI
    /// or returns an error if the request is invalid or unauthorized. This approach enhances security by minimizing
    /// the exposure of sensitive information in subsequent authorization requests.
    /// </remarks>
    Task<AuthorizationResponse> HandleAsync(
        AuthorizationRequest authorizationRequest,
        ClientRequest clientRequest);
}
