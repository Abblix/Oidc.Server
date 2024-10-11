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

using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using static Abblix.Oidc.Server.Model.AuthorizationRequest;

namespace Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

/// <summary>
/// Handles fetching of authorization request objects from a specified request URI.
/// This class is responsible for retrieving the pre-registered request objects from an external location
/// indicated by a URI, ensuring the request is complete and valid.
/// It helps enable dynamic request objects, allowing authorization servers to fetch additional
/// data required for processing the authorization request.
/// </summary>
public class RequestUriFetcher : IAuthorizationRequestFetcher
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RequestUriFetcher"/> class.
    /// This constructor sets up the necessary services for fetching the request objects over HTTP.
    /// </summary>
    /// <param name="logger">The logger used for logging warnings when request fetching fails.</param>
    /// <param name="httpClientFactory">
    /// The factory used to create <see cref="HttpClient"/> instances for making HTTP requests to the specified URI.
    /// </param>
    public RequestUriFetcher(
        ILogger<RequestUriFetcher> logger,
        IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
    }

    private readonly ILogger _logger;
    private readonly IHttpClientFactory _httpClientFactory;


    /// <summary>
    /// Asynchronously fetches the authorization request object from the given request URI.
    /// This method retrieves the request object if the request URI is valid and contains an absolute URL.
    /// It then returns the authorization request object or logs an error if the fetch fails.
    /// </summary>
    /// <param name="request">The authorization request, which contains the RequestUri.</param>
    /// <returns>
    /// A task representing the asynchronous operation, with the result being the fetched request object or an error.
    /// </returns>
    /// <remarks>
    /// The method checks for conflicts between the `Request` and `RequestUri` parameters.
    /// If both are present, it returns an error since only one should be used.
    /// Otherwise, it proceeds to fetch the request object from the `RequestUri` and returns the result.
    /// </remarks>
    public async Task<FetchResult> FetchAsync(AuthorizationRequest request)
    {
        if (request is { Request: not null, RequestUri: not null })
        {
            // Log an error if both request parameters are provided, as this violates the request format rules.
            return ErrorFactory.InvalidRequest(
                $"Only one of the parameters {Parameters.Request} and {Parameters.RequestUri} can be used");
        }

        if (request is not { RequestUri: { IsAbsoluteUri: true } requestUri })
        {
            return request;
        }

        // If the request contains a valid absolute URI, proceed to fetch the request object.
        var client = _httpClientFactory.CreateClient();
        string requestObject;
        try
        {
            requestObject = await client.GetStringAsync(requestUri);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Unable to get the request object from {RequestUri}", requestUri);
            return ErrorFactory.InvalidRequestUri(
                $"Unable to get the request object from {Parameters.RequestUri}");
        }

        // Return the updated request with the fetched request object and nullify the redirect URI.
        return request with { RedirectUri = null, Request = requestObject };
    }
}
