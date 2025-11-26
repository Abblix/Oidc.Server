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

using Abblix.Utils;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

/// <summary>
/// Defines an interface for fetching the details of an authorization request, potentially including resolving and
/// validating a request object.
/// </summary>
public interface IAuthorizationRequestFetcher
{
    /// <summary>
    /// Asynchronously fetches and processes the authorization request, which may involve resolving a request object
    /// from a URI or directly from the request parameters.
    /// </summary>
    /// <param name="request">
    /// The initial authorization request, which may contain a reference to a request object or inline request parameters.
    /// </param>
    /// <returns>
    /// A task that returns the processed authorization request
    /// details, encapsulated within a <see cref="FetchResult"/>.</returns>
    /// <remarks>
    /// This method is responsible for handling the specifics of fetching and interpreting the authorization request,
    /// which may include retrieving a request object from a remote location specified by the 'request_uri' parameter,
    /// or validating the request object provided inline via the 'request' parameter. It ensures the request adheres
    /// to the expected format and validation requirements before further processing.
    /// </remarks>
    Task<Result<AuthorizationRequest, AuthorizationRequestValidationError>> FetchAsync(AuthorizationRequest request);
}
