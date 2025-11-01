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
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains a <see cref="Result{T, AuthError}"/> object,
    /// which either represents a successfully processed request or an error indicating issues with the JWT validation.
    /// </returns>
    /// <remarks>
    /// This method is responsible for decoding and validating the JWT contained in the request. If the JWT is valid,
    /// the payload is bound to the request model.
    /// If the JWT is invalid or not present, an appropriate error result is returned.
    /// </remarks>
    Task<Result<T, OidcError>> FetchAsync<T>(T request, string? requestObject)
        where T : class;
}
