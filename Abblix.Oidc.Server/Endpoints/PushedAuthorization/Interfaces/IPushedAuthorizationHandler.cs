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
