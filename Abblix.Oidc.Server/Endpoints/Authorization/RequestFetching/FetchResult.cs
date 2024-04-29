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
