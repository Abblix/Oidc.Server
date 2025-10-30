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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Manages the removal of registered clients from the authorization server, ensuring that requests for client
/// unregistration are handled securely and in accordance with OAuth 2.0 and OpenID Connect standards.
/// </summary>
public class RemoveClientHandler : IRemoveClientHandler
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RemoveClientHandler"/> class with the specified validator
    /// and processor services.
    /// </summary>
    /// <param name="validator">The service used to validate incoming client removal requests.</param>
    /// <param name="processor">The service responsible for processing validated removal requests and unregistering
    /// the client.</param>
    public RemoveClientHandler(
        IClientRequestValidator validator,
        IRemoveClientRequestProcessor processor)
    {
        _validator = validator;
        _processor = processor;
    }

    private readonly IClientRequestValidator _validator;
    private readonly IRemoveClientRequestProcessor _processor;

    /// <summary>
    /// Asynchronously processes a request to remove a registered client, ensuring the request is valid and authorized
    /// before proceeding with client unregistration.
    /// </summary>
    /// <param name="clientRequest">The client request containing necessary information for identifying and removing
    /// the specified client.</param>
    /// <returns>A task that results in a <see cref="Result{RemoveClientSuccessfulResponse, AuthError}"/>, which encapsulates the outcome of
    /// the removal process, including success or error information.</returns>
    /// <remarks>
    /// This method follows a two-step process: first, validating the removal request to ensure it meets all
    /// required criteria and is authorized; second, if validation succeeds, processing the request to unregister
    /// the client from the system. This approach ensures that client removal is managed securely and aligns with
    /// best practices in client management within OAuth 2.0 and OpenID Connect frameworks.
    /// </remarks>
    public async Task<Result<RemoveClientSuccessfulResponse, AuthError>> HandleAsync(ClientRequest clientRequest)
    {
        var validationResult = await _validator.ValidateAsync(clientRequest);

        return await validationResult.BindAsync(_processor.ProcessAsync);
    }
}
