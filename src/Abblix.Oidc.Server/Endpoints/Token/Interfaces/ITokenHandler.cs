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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Defines a contract for handling OAuth 2.0 token requests, encompassing validation, processing, and issuance
/// of tokens based on authorization grants.
/// </summary>
public interface ITokenHandler
{
    /// <summary>
    /// Asynchronously handles a token request, validating the request details and, if valid, processing it to issue,
    /// renew or exchange tokens according to OAuth 2.0 and OpenID Connect standards.
    /// </summary>
    /// <param name="tokenRequest">The token request containing essential parameters such as the grant type,
    /// client credentials, and other parameters pertinent to the token issuance process.</param>
    /// <param name="clientRequest">Supplementary information about the client making the request, necessary
    /// for performing contextual validation and ensuring the request complies with security policies.</param>
    /// <returns>
    /// A <see cref="Task"/> resulting in a <see cref="TokenIssued"/> on success, which contains the issued tokens
    /// (access token, refresh token, ID token, etc.), or an <see cref="OidcError"/> describing the reason
    /// for request failure.
    /// </returns>
    /// <remarks>
    /// Implementations of this interface are critical to the secure and compliant functioning of an OAuth 2.0
    /// authorization server. They must ensure that only valid and authorized requests lead to the issuance of tokens,
    /// thereby maintaining the integrity and security of the authentication and authorization process.
    /// </remarks>
    [Obsolete("Implement and call the overload taking a CancellationToken. This one is kept so an existing " +
              "implementation keeps working, and will be removed in the next major version.")]
    Task<Result<TokenIssued, OidcError>> HandleAsync(TokenRequest tokenRequest, ClientRequest clientRequest)
        => HandleAsync(tokenRequest, clientRequest, CancellationToken.None);

    /// <inheritdoc cref="HandleAsync(TokenRequest, ClientRequest)"/>
    /// <param name="tokenRequest">The token request.</param>
    /// <param name="clientRequest">Supplementary information about the client making the request.</param>
    /// <param name="cancellationToken">
    /// Abandons the request when the caller stops waiting. The adapters pass the request's own token, so a
    /// client that disconnects mid-request stops the work it started rather than leaving it to run out its
    /// own timeout: CIBA holds this call open for the whole long-polling window.
    /// </param>
    /// <remarks>
    /// This is the member an implementation provides. The obsolete overload above defaults to forwarding here,
    /// so a caller still holding the old signature keeps working, while an implementation that provided only
    /// the old one fails to compile rather than silently never receiving the token.
    /// </remarks>
    Task<Result<TokenIssued, OidcError>> HandleAsync(
        TokenRequest tokenRequest, ClientRequest clientRequest, CancellationToken cancellationToken);
}
