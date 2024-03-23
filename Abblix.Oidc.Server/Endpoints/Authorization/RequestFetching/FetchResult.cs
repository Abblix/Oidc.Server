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

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

/// <summary>
/// Represents the result of fetching an authorization request, either successful with the request data or
/// indicating a fault with an associated error.
/// </summary>
public abstract record FetchResult
{
    /// <summary>
    /// Converts an <see cref="AuthorizationRequest"/> to a <see cref="FetchResult"/> indicating a successful
    /// fetch operation.
    /// </summary>
    /// <param name="request">The successfully fetched authorization request.</param>
    public static implicit operator FetchResult(AuthorizationRequest request)
        => new Success(request);

    /// <summary>
    /// Converts an <see cref="AuthorizationRequestValidationError"/> to a <see cref="FetchResult"/> indicating
    /// a fault during fetch operation.
    /// </summary>
    /// <param name="error">The error occurred while fetching the authorization request.</param>
    public static implicit operator FetchResult(AuthorizationRequestValidationError error)
        => new Fault(error);

    /// <summary>
    /// Represents a successful fetch result containing the authorization request.
    /// </summary>
    public record Success(AuthorizationRequest Request) : FetchResult;

    /// <summary>
    /// Represents a fault in fetching the authorization request, encapsulating the associated error.
    /// </summary>
    public record Fault(AuthorizationRequestValidationError Error) : FetchResult;
}
