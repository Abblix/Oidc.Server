// Abblix OIDC Client Library
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

using System.Text.Json.Nodes;

namespace Abblix.Oidc.Client.Features.UserInfo;

/// <summary>
/// Reads the claims the provider will tell about the user an access token was issued for
/// (OpenID Connect Core 1.0 section 5.3).
/// </summary>
public interface IUserInfoService
{
    /// <summary>
    /// Fetches the UserInfo claims for <paramref name="accessToken"/>, or throws
    /// <see cref="UserInfoException"/> when they cannot be trusted or the endpoint refused.
    /// </summary>
    /// <param name="accessToken">The access token the authorization produced.</param>
    /// <param name="expectedSubject">
    /// The <c>sub</c> of the ID Token this login produced, which the response must name.
    /// </param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The claims, as the provider stated them.</returns>
    /// <remarks>
    /// The subject is required rather than optional because section 5.3.2 makes comparing it the caller's
    /// duty - "the Client MUST verify that the sub Claim in the UserInfo Response is identical to the sub
    /// Claim in the ID Token" - and a duty that can be skipped by omitting an argument is one that will
    /// be. Passing it is the only way to call this at all.
    /// </remarks>
    Task<JsonObject> GetAsync(
        string accessToken,
        string expectedSubject,
        CancellationToken cancellationToken = default);
}
