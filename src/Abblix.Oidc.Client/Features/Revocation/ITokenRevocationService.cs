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


namespace Abblix.Oidc.Client.Features.Revocation;

/// <summary>
/// Asks the provider to revoke a token this client holds (RFC 7009).
/// </summary>
public interface ITokenRevocationService
{
    /// <summary>
    /// Revokes <paramref name="token"/> at the provider's revocation endpoint.
    /// </summary>
    /// <param name="token">The token to revoke.</param>
    /// <param name="tokenTypeHint">
    /// Which kind of token it is, from <see cref="TokenTypeHints"/>. Optional, and only a hint about where
    /// the provider should look first.
    /// </param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <remarks>
    /// Returning normally means the provider answered that the token is gone - which RFC 7009 section 2.2
    /// also says of a token it never knew: it "responds with HTTP status code 200 if the token has been
    /// revoked successfully or if the client submitted an invalid token". The two are deliberately
    /// indistinguishable, so this method cannot report which happened, and a caller must not read success as
    /// proof that the token was ever valid.
    /// </remarks>
    /// <exception cref="TokenRevocationException">
    /// The provider refused the request, or could not be reached. When
    /// <see cref="TokenRevocationException.TokenMayStillExist"/> is set, the token was not revoked.
    /// </exception>
    Task RevokeAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default);
}
