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

using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Handles the backend logic for processing requests to remove clients from the system. This processor uses the provided
/// client information manager to execute the removal operation.
/// </summary>
public class RemoveClientRequestProcessor : IRemoveClientRequestProcessor
{
    /// <summary>
    /// Constructs a new instance of the <see cref="RemoveClientRequestProcessor"/> class, initializing it with
    /// the necessary components to manage client information and perform removal operations.
    /// </summary>
    /// <param name="clientInfoManager">An instance of <see cref="IClientInfoManager"/> used to interact with and
    /// manage client information, facilitating the removal of clients based on their identifiers.</param>
    public RemoveClientRequestProcessor(IClientInfoManager clientInfoManager)
    {
        _clientInfoManager = clientInfoManager;
    }

    private readonly IClientInfoManager _clientInfoManager;

    /// <summary>
    /// Asynchronously executes the process of removing a client based on the provided request.
    /// This method ensures the client specified in the request is removed from the system,
    /// reflecting changes in the client registry.
    /// </summary>
    /// <param name="request">An instance of <see cref="ValidClientRequest"/> containing the details of
    /// the client to be removed, including its unique identifier.</param>
    /// <returns>A task that, upon completion, yields a <see cref="RemoveClientResponse"/> indicating the successful
    /// removal of the client.</returns>
    /// <remarks>
    /// This method calls upon the <see cref="IClientInfoManager"/> to remove the specified client.
    /// It is expected that the request passed to this method has been validated beforehand,
    /// ensuring that the client exists and the initiator of the request has the authority to perform
    /// the removal operation.
    /// </remarks>
    public async Task<RemoveClientResponse> ProcessAsync(ValidClientRequest request)
    {
        await _clientInfoManager.RemoveClientAsync(request.ClientInfo.ClientId);
        return new RemoveClientSuccessfulResponse();
    }
}
