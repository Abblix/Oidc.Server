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


namespace Abblix.Oidc.Client.Features.ProtectedResources;

/// <summary>
/// Where the access token for an outgoing call comes from.
/// </summary>
/// <remarks>
/// The seam a host reaches for when the ready-made answer does not fit: a background job with no signed-in
/// user, a client-credentials token, a cache, a refresh policy of the host's own choosing.
/// Implementations must be safe to use from any thread and must not hold per-user state in fields. The
/// object outlives every request that uses it: message handlers are pooled by
/// <see cref="IHttpClientFactory"/> for minutes at a time, so an instance that remembered a user would hand
/// that user's token to whoever called next. Read ambient state per call.
/// </remarks>
public interface IAccessTokenSource
{
    /// <summary>
    /// Supplies the token to present for this request.
    /// </summary>
    /// <param name="request">Which resource is being called, and where exactly.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>The token and the scheme to present it under.</returns>
    /// <exception cref="AccessTokenUnavailableException">
    /// No token can be supplied. The reason distinguishes a missing session from a missing token from an
    /// expired one.
    /// </exception>
    Task<AccessToken> GetTokenAsync(
        AccessTokenRequest request, CancellationToken cancellationToken = default);
}
