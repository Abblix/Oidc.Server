// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
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
    [SuppressMessage("Major Code Smell", "S1133:Deprecated code should be removed",
        Justification = "Removal is scheduled and tracked: the overload is kept only so a caller written against the pre-2.4 signature keeps working, and it goes in the next major version (#302).")]
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
