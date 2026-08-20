// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.RequestObject;

/// <summary>
/// Defines the interface for fetching and processing JWT request objects, validating their content
/// and binding their payloads to a request model.
/// This is typically used in OpenID Connect flows where request parameters are passed as JWTs.
/// </summary>
public interface IRequestObjectFetcher
{
    /// <summary>
    /// Fetches and processes the request object by validating its JWT and binding the payload to the request model.
    /// </summary>
    /// <typeparam name="T">The type of the request model.</typeparam>
    /// <param name="request">The initial request model to bind the JWT payload to.</param>
    /// <param name="requestObject">The JWT contained within the request, if any.</param>
    /// <param name="requiredSigningAlgorithm">Optional selector returning the algorithm the resolved
    /// client registered for this kind of request object (e.g. <c>request_object_signing_alg</c> for
    /// authorization requests or <c>backchannel_authentication_request_signing_alg</c> for CIBA). When
    /// it returns a non-empty value, a request object whose <c>alg</c> differs is rejected.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains a <see cref="Result{T, AuthError}"/> object,
    /// which either represents a successfully processed request or an error indicating issues with the JWT validation.
    /// </returns>
    /// <remarks>
    /// This method is responsible for decoding and validating the JWT contained in the request. If the JWT is valid,
    /// the payload is bound to the request model.
    /// If the JWT is invalid or not present, an appropriate error result is returned.
    /// </remarks>
    Task<Result<T, OidcError>> FetchAsync<T>(
        T request,
        string? requestObject,
        Func<ClientInfo, string?>? requiredSigningAlgorithm = null)
        where T : class;
}
