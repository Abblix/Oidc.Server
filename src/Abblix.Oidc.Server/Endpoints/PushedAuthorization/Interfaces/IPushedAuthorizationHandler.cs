// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

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
    /// <param name="authorizationRequest">An instance of <see cref="Model.AuthorizationRequest"/> representing the details
    /// of the authorization request submitted by the client.</param>
    /// <param name="clientRequest">An instance of <see cref="Model.ClientRequest"/> providing additional information about
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
        Model.AuthorizationRequest authorizationRequest,
        Model.ClientRequest clientRequest);
}
