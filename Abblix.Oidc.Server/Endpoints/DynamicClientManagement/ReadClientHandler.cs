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
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Handles requests for reading client configurations from the authorization server.
/// Validates and processes requests to retrieve information about registered clients.
/// </summary>
public class ReadClientHandler : IReadClientHandler
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ReadClientHandler"/> class with specified validator and processor
    /// services.
    /// </summary>
    /// <param name="validator">The service used to validate client information requests.</param>
    /// <param name="processor">The service responsible for processing valid client information requests and retrieving
    /// client data.</param>
    public ReadClientHandler(
        IClientRequestValidator validator,
        IReadClientRequestProcessor processor)
    {
        _validator = validator;
        _processor = processor;
    }

    private readonly IClientRequestValidator _validator;
    private readonly IReadClientRequestProcessor _processor;

    /// <summary>
    /// Asynchronously handles a request to read client information, validating the request and processing it to return
    /// the requested client data.
    /// </summary>
    /// <param name="clientRequest">The client request containing details necessary for fetching the client information,
    /// such as the client identifier.</param>
    /// <returns>A task that results in a <see cref="ReadClientResponse"/>, which could be the requested client data or
    /// an error response.</returns>
    /// <exception cref="UnexpectedTypeException">Thrown if the validation result does not match expected types.
    /// </exception>
    /// <remarks>
    /// This method serves as a critical part of dynamic client management, allowing for the secure retrieval of client
    /// configurations. It ensures that only valid requests are processed, safeguarding against unauthorized access
    /// to client information.
    /// </remarks>
    public async Task<Result<ReadClientSuccessfulResponse, OidcError>> HandleAsync(Model.ClientRequest clientRequest)
    {
        var validationResult = await _validator.ValidateAsync(clientRequest);

        return await validationResult.BindAsync(_processor.ProcessAsync);
    }
}
