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

using Abblix.Oidc.Server.Model;
using AuthorizationResponse = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse;

namespace Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;

/// <summary>
/// Represents the response to a pushed authorization request. This response includes the URI
/// where the authorization request is stored and the duration for which the request will remain valid.
/// </summary>
public record PushedAuthorizationResponse(AuthorizationRequest Model, Uri RequestUri, TimeSpan ExpiresIn)
    : AuthorizationResponse(Model)
{
    /// <summary>
    /// The URI where the authorization request is stored.
    /// This URI is used by the client to refer to the authorization request in subsequent operations.
    /// </summary>
    public Uri RequestUri { get; init; } = RequestUri;

    /// <summary>
    /// The duration for which the authorization request is considered valid.
    /// After this period, the request may no longer be retrievable or usable.
    /// </summary>
    public TimeSpan ExpiresIn { get; init; } = ExpiresIn;
};
