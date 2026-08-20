// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// A task that returns the processed authorization request details, encapsulated within a
    /// <see cref="Result{TSuccess,TFailure}"/> of <see cref="AuthorizationRequest"/> on success or
    /// <see cref="AuthorizationRequestValidationError"/> on failure.</returns>
    /// <remarks>
    /// This method is responsible for handling the specifics of fetching and interpreting the authorization request,
    /// which may include retrieving a request object from a remote location specified by the 'request_uri' parameter,
    /// or validating the request object provided inline via the 'request' parameter. It ensures the request adheres
    /// to the expected format and validation requirements before further processing.
    /// </remarks>
    Task<Result<AuthorizationRequest, AuthorizationRequestValidationError>> FetchAsync(AuthorizationRequest request);
}
