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

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Defines a contract for handling requests to remove or unregister clients from the authorization server.
/// </summary>
public interface IRemoveClientHandler
{
    /// <summary>
    /// Asynchronously processes a request for client removal, validating and executing the unregistration based
    /// on the provided client information.
    /// </summary>
    /// <param name="clientRequest">
    /// The client request containing the necessary information to identify the client to be removed.</param>
    /// <returns>A task that results in a <see cref="RemoveClientResponse"/>, encapsulating the outcome of the client
    /// removal process, which can be a confirmation of successful removal or details of any errors encountered.
    /// </returns>
    /// <remarks>
    /// This method is crucial for maintaining the security and integrity of the client registry within an OAuth 2.0
    /// and OpenID Connect framework. It ensures that only authorized and validated requests result in the removal of
    /// a client, adhering to the standards and practices of dynamic client management.
    /// </remarks>
    Task<RemoveClientResponse> HandleAsync(ClientRequest clientRequest);
}
