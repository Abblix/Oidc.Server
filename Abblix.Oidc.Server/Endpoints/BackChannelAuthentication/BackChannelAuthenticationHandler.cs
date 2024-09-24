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
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.RequestFetching;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication;

/// <summary>
/// Handles the backchannel authentication process for a CIBA (Client-Initiated Backchannel Authentication) request.
/// This handler coordinates the fetching, validation, and processing of the authentication request.
/// </summary>
public class BackChannelAuthenticationHandler : IBackChannelAuthenticationHandler
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BackChannelAuthenticationHandler"/> class, with dependencies for
    /// fetching, validating, and processing backchannel authentication requests.
    /// </summary>
    /// <param name="fetcher">The service responsible for fetching and validating the initial authentication request.
    /// </param>
    /// <param name="validator">The service responsible for validating the fetched authentication request.</param>
    /// <param name="processor">The service responsible for processing the validated authentication request and
    /// generating the response.</param>
    public BackChannelAuthenticationHandler(
        IBackChannelAuthenticationRequestFetcher fetcher,
        IBackChannelAuthenticationRequestValidator validator,
        IBackChannelAuthenticationRequestProcessor processor)
    {
        _fetcher = fetcher;
        _validator = validator;
        _processor = processor;
    }

    private readonly IBackChannelAuthenticationRequestFetcher _fetcher;
    private readonly IBackChannelAuthenticationRequestValidator _validator;
    private readonly IBackChannelAuthenticationRequestProcessor _processor;

    /// <summary>
    /// Handles the entire backchannel authentication process by first fetching the request, then validating it,
    /// and finally processing it to generate an appropriate response.
    /// </summary>
    /// <param name="request">The initial backchannel authentication request to be processed.</param>
    /// <param name="clientRequest">The client request information associated with the authentication request.</param>
    /// <returns>A task that represents the asynchronous operation,
    /// resulting in a <see cref="BackChannelAuthenticationResponse"/> that indicates the outcome of the process.
    /// </returns>
    public async Task<BackChannelAuthenticationResponse> HandleAsync(
        BackChannelAuthenticationRequest request,
        ClientRequest clientRequest)
    {
        // Fetch the request if necessary
        var fetchResult = await _fetcher.FetchAsync(request);
        switch (fetchResult)
        {
            case OperationResult<BackChannelAuthenticationRequest>.Success(var requestObject):
                request = requestObject;
                break;

            case OperationResult<BackChannelAuthenticationRequest>.Error(var error, var description):
                return new BackChannelAuthenticationError(error, description);

            default:
                throw new UnexpectedTypeException(nameof(fetchResult), fetchResult.GetType());
        }

        // Validate the fetched request
        var validationResult = await _validator.ValidateAsync(request, clientRequest);

        // Process the validated request or handle validation errors
        return validationResult switch
        {
            ValidBackChannelAuthenticationRequest validRequest => await _processor.ProcessAsync(validRequest),

            BackChannelAuthenticationValidationError { Error: var error, ErrorDescription: var description }
                => new BackChannelAuthenticationError(error, description),

            _ => throw new UnexpectedTypeException(nameof(validationResult), validationResult.GetType()),
        };
    }
}
