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


namespace Abblix.Oidc.Client.Features.Tokens;

/// <summary>
/// Talks to the OpenID Provider's token endpoint.
/// </summary>
public interface ITokenRequestService
{
    /// <summary>
    /// Exchanges an authorization code for tokens.
    /// </summary>
    /// <param name="code">The code the provider returned to the callback.</param>
    /// <param name="codeVerifier">The secret half of the PKCE pair kept from the request.</param>
    /// <param name="redirectUri">
    /// The redirect address of the original request, which the provider compares against what it recorded.
    /// </param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="TokenRequestException">The provider refused, or could not be reached.</exception>
    Task<TokenResponse> ExchangeCodeAsync(
        string code, string codeVerifier, string redirectUri, CancellationToken cancellationToken = default);

    /// <summary>
    /// Trades a refresh token for a fresh set of tokens.
    /// </summary>
    /// <param name="refreshToken">The refresh token held for the session.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="TokenRequestException">
    /// The provider refused, or could not be reached. A refusal carrying
    /// <see cref="ErrorCodes.InvalidGrant"/> means this token has been rotated away.
    /// </exception>
    Task<TokenResponse> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default);
}
