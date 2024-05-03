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
