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

using Abblix.Oidc.Client.Features.Tokens;

namespace Abblix.Oidc.Client.Features.PasswordGrant;

/// <summary>
/// Trades an end-user's own username and password for tokens (RFC 6749 section 4.3).
/// </summary>
/// <remarks>
/// RFC 9700 section 2.4 states flatly that "the resource owner password credentials grant MUST NOT be used",
/// and gives five reasons: it exposes the user's credentials to the client; it widens the attack surface,
/// since the credentials can now leak from more places than the authorization server alone; it teaches users
/// to type their password into things that are not their provider; it has no way to carry a second factor or
/// any multi-step authentication; and it cannot express credentials bound to a web origin, which is what a
/// passkey is.
///
/// It is implemented here regardless, because a client library meets providers as they are and some of them
/// offer nothing else. What the prohibition buys is the shape of this feature rather than its absence: the
/// grant lives on its own service behind its own registration, so a host reaches it only by naming it, and an
/// audit can find every application that did with one search. Nothing registered by <c>AddTokenRequests</c>
/// can perform it.
/// </remarks>
public interface IPasswordGrantService
{
    /// <summary>
    /// Presents the end-user's credentials and asks for tokens.
    /// </summary>
    /// <param name="username">The end-user's identifier at the provider.</param>
    /// <param name="password">The end-user's password.</param>
    /// <param name="scopes">
    /// What the tokens are to be good for. Optional per RFC 6749 section 4.3.2; pass none and the provider
    /// decides.
    /// </param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>
    /// The provider's answer. RFC 6749 section 4.3.3 says a refresh token SHOULD be included, which is the
    /// one mercy of this grant: with one, the application need not keep the password to stay signed in.
    /// </returns>
    /// <exception cref="TokenRequestException">The provider refused, or could not be reached.</exception>
    Task<TokenResponse> RequestTokensAsync(
        string username,
        string password,
        IReadOnlyCollection<string>? scopes = null,
        CancellationToken cancellationToken = default);
}
