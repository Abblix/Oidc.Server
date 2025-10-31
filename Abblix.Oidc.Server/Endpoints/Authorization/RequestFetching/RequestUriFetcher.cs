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

using System.Net;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Features.UriValidation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using static Abblix.Oidc.Server.Model.AuthorizationRequest;
using AuthorizationErrorFactory = Abblix.Oidc.Server.Endpoints.Authorization.Validation.ErrorFactory;

namespace Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

/// <summary>
/// Handles fetching of authorization request objects from a specified request URI.
/// This class is responsible for retrieving pre-registered request objects from an external location
/// indicated by a URI, ensuring the request is complete and valid.
/// It enables dynamic request objects, allowing authorization servers to fetch additional
/// data required for processing the authorization request.
/// </summary>
/// <param name="logger">The logger used for logging warnings when request fetching fails.</param>
/// <param name="clientInfoProvider">Service to retrieve client-specific information for validation.</param>
/// <param name="secureHttpFetcher">The secure HTTP fetcher for retrieving content from external URIs with SSRF protection.</param>
public class RequestUriFetcher(
    ILogger<RequestUriFetcher> logger,
    IClientInfoProvider clientInfoProvider,
    ISecureHttpFetcher secureHttpFetcher) : IAuthorizationRequestFetcher
{
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
    public async Task<Result<AuthorizationRequest, AuthorizationRequestValidationError>> FetchAsync(AuthorizationRequest request)
    {
        if (request is { Request: not null, RequestUri: not null })
        {
            return AuthorizationErrorFactory.InvalidRequest(
                $"Only one of the parameters {Parameters.Request} and {Parameters.RequestUri} can be used");
        }

        if (request is not { RequestUri: { IsAbsoluteUri: true } requestUri })
        {
            return request; // Pass through if no valid RequestUri is provided
        }

        if (requestUri.Scheme != Uri.UriSchemeHttps)
        {
            return AuthorizationErrorFactory.ValidationError(
                ErrorCodes.InvalidRequestUri, "The request URI must be an https URI");
        }

        var clientId = request.ClientId;
        if (clientId is null)
        {
            return AuthorizationErrorFactory.ValidationError(
                ErrorCodes.UnauthorizedClient, "The client id is required");
        }

        var clientInfo = await clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
        if (clientInfo == null)
        {
            logger.LogWarning("The client with id {ClientId} was not found", Sanitized.Value(clientId));
            return AuthorizationErrorFactory.ValidationError(
                ErrorCodes.UnauthorizedClient, "The client is not authorized");
        }

        var requestUriValidator = UriValidatorFactory.Create(true, clientInfo.RequestUris);
        if (!requestUriValidator.IsValid(requestUri))
        {
            return AuthorizationErrorFactory.ValidationError(
                ErrorCodes.InvalidRequestUri, "The request URI is not allowed for the client");
        }

        // SSRF validation is handled by the ISecureHttpFetcher decorator
        var contentResult = await secureHttpFetcher.FetchStringAsync(requestUri);

        if (contentResult.TryGetFailure(out var contentError))
        {
            return AuthorizationErrorFactory.InvalidRequestUri(contentError.ErrorDescription);
        }

        var requestObject = contentResult.GetSuccess();

        // Return the updated request with the fetched request object and nullify the redirect URI
        return request with { RedirectUri = null, Request = requestObject };
    }
}
