// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
//
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
//
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
//
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
//
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
//
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
//
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
    /// A task that represents the asynchronous operation. The task result contains the processed authorization request
    /// details, encapsulated within a <see cref="FetchResult"/>.</returns>
    /// <remarks>
    /// This method is responsible for handling the specifics of fetching and interpreting the authorization request,
    /// which may include retrieving a request object from a remote location specified by the 'request_uri' parameter,
    /// or validating the request object provided inline via the 'request' parameter. It ensures the request adheres
    /// to the expected format and validation requirements before further processing.
    /// </remarks>
    Task<FetchResult> FetchAsync(AuthorizationRequest request);
}
