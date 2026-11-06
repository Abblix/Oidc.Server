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
/// The source a host gets when it wired a resource client but never said where tokens come from.
/// </summary>
/// <remarks>
/// It refuses, loudly and by name. The alternative - quietly sending the request without a token - produces
/// a 401 from the resource server that reads exactly like an expired token, and everyone spends the
/// afternoon looking at the provider.
/// </remarks>
internal sealed class NoAccessTokenSource : IAccessTokenSource
{
    /// <inheritdoc />
    public Task<AccessToken> GetTokenAsync(
        AccessTokenRequest request, CancellationToken cancellationToken = default)
        => throw new AccessTokenUnavailableException(
            AccessTokenUnavailableReason.NoAmbientSession,
            $"No access token source is registered, so nothing can be presented to '{request.Resource}'. "
            + "Call AddSessionAccessTokenSource() to take the token from the signed-in user's session, or "
            + "AddAccessTokenSource<T>() to supply one of your own.");
}
