// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
public partial class RequestUriFetcher(
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
    public async Task<Result<AuthorizationRequest, AuthorizationRequestValidationError>> FetchAsync(
        AuthorizationRequest request)
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
            LogClientNotFound(clientId);
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
        var contentResult = await secureHttpFetcher.FetchAsync<string>(requestUri);

        return contentResult.Match<Result<AuthorizationRequest, AuthorizationRequestValidationError>>(
            requestObject => request with { RedirectUri = null, Request = requestObject },
            contentError => AuthorizationErrorFactory.InvalidRequestUri(contentError.ErrorDescription));
    }
}
