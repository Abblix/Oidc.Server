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
/// Fetches authorization request objects from a specified request URI.
/// </summary>
public class RequestUriFetcher : IAuthorizationRequestFetcher
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RequestUriFetcher"/> class.
    /// </summary>
    /// <param name="logger">The logger used for logging warnings when unable to fetch the request object.</param>
    /// <param name="httpClientFactory">
    /// The factory used to create instances of <see cref="HttpClient"/> for making HTTP requests.</param>
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
    /// Asynchronously fetches the authorization request object from the specified request URI.
    /// </summary>
    /// <param name="request">
    /// The authorization request containing a RequestUri from which to fetch the request object.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains the authorization request object
    /// fetched from the URI or an error.</returns>
    /// <remarks>
    /// If the authorization request contains a valid absolute URI in the RequestUri property,
    /// this method attempts to fetch the request object from that URI.
    /// If the fetch operation is successful, the request object is returned; otherwise, an error is logged,
    /// and an error response is returned.
    /// </remarks>
    public async Task<FetchResult> FetchAsync(AuthorizationRequest request)
    {
        if (request is { Request: not null, RequestUri: not null })
        {
            return ErrorFactory.InvalidRequest(
                $"Only one of the parameters {Parameters.Request} and {Parameters.RequestUri} can be used");
        }

        if (request is { RequestUri: { IsAbsoluteUri: true } requestUri })
        {
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

            return request with { RedirectUri = null, Request = requestObject };
        }

        return request;
    }
}
