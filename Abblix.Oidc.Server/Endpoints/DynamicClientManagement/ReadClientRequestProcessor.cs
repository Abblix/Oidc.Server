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

using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Handles the processing of requests to retrieve stored client information, ensuring that such requests
/// are valid and authorized. This class serves as a bridge between the request validation and the actual
/// retrieval of client details from the system's data store.
/// </summary>
public class ReadClientRequestProcessor : IReadClientRequestProcessor
{
    /// <summary>
    /// Asynchronously retrieves the details of a client based on a valid request.
    /// This method ensures that only authorized and valid requests lead to the disclosure of client information.
    /// </summary>
    /// <param name="request">A <see cref="ValidClientRequest"/> object containing the identification details
    /// of the client whose information is being requested.</param>
    /// <returns>
    /// A <see cref="Task"/> that, upon completion, yields a <see cref="ReadClientResponse"/> containing the details
    /// of the client. The response includes information such as the client's ID, redirect URIs, and the URL for
    /// initiating login, among other possible client configuration details.
    /// </returns>
    /// <remarks>
    /// This method is essential for supporting features like dynamic client registration and management in OAuth 2.0
    /// and OpenID Connect ecosystems. It allows clients or administrators to query the system for the configuration
    /// of registered clients, facilitating transparency and ease of management. Note that sensitive information,
    /// like client secrets, are not directly retrievable to maintain security.
    /// </remarks>
    public Task<ReadClientResponse> ProcessAsync(ValidClientRequest request)
    {
        var client = request.ClientInfo;

        //TODO add missing properties
        return Task.FromResult<ReadClientResponse>(
            new ReadClientSuccessfulResponse
            {
                ClientId = client.ClientId,
                //ClientSecret = we do not store secrets in initial forms, only hashes
                RedirectUris = client.RedirectUris,
                InitiateLoginUri = client.InitiateLoginUri,
            });
    }
}
