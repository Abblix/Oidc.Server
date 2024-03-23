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
/// Defines a contract for handling requests to read client configurations, as part of client management in OAuth 2.0
/// and OpenID Connect frameworks.
/// </summary>
public interface IReadClientHandler
{
    /// <summary>
    /// Asynchronously handles a request to retrieve a client's configuration details.
    /// </summary>
    /// <param name="clientRequest">The client request containing the necessary information to identify the client
    /// whose configuration is to be read.</param>
    /// <returns>A task that results in a <see cref="ReadClientResponse"/>, which may either contain the client's
    /// configuration details if the request is valid, or an error response indicating the reason for failure.</returns>
    /// <remarks>
    /// This method processes the incoming request to read a client's configuration. It first validates the request
    /// to ensure that it meets the necessary criteria and that the client specified in the request exists and is
    /// accessible by the requester. Upon successful validation, the method retrieves and returns the client's
    /// configuration details. If the request is invalid or if the client cannot be found, an appropriate error
    /// response is generated.
    /// </remarks>
    Task<ReadClientResponse> HandleAsync(Model.ClientRequest clientRequest);
}
