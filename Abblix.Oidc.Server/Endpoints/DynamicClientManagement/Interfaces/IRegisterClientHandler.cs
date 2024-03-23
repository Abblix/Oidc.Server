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

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Defines a contract for handling dynamic client registration requests in compliance with OAuth 2.0 and
/// OpenID Connect protocols.
/// </summary>
public interface IRegisterClientHandler
{
    /// <summary>
    /// Asynchronously processes a client registration request, validating its content and, if valid,
    /// registering the client with the authorization server.
    /// </summary>
    /// <param name="clientRegistrationRequest">The client registration request containing the necessary parameters
    /// for registering a new client, such as client metadata.</param>
    /// <returns>A task that results in a <see cref="ClientRegistrationResponse"/>, encapsulating either the successful
    /// registration details of the new client or an error response indicating the reasons for registration failure.
    /// </returns>
    /// <remarks>
    /// This method is responsible for the entire lifecycle of a client registration request, from initial validation
    /// against the OAuth 2.0 and OpenID Connect specifications to processing the request and generating a response.
    /// It ensures that all registered clients adhere to the protocol's requirements and the authorization server's
    /// policies.
    /// </remarks>
    Task<ClientRegistrationResponse> HandleAsync(Model.ClientRegistrationRequest clientRegistrationRequest);
}
