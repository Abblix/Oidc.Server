// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.TokenExchange;

/// <summary>
/// The key a subject_token is bound to, carried into the exchange so the token endpoint requires its proof from the
/// client the token was issued to, whichever kind of token the subject_token is.
/// </summary>
/// <remarks>
/// This is the server's policy rather than a clause of RFC 8693: a sender-constrained token (RFC 9700 sections 2.2.1 and
/// 2.2.2) must not buy new tokens for whoever holds it without its key. The client the token was issued to is the one
/// that holds the key, so it is held to the binding; another client exchanging the token through
/// <see cref="ClientInfo.AllowCrossClientSubjectTokenExchange"/>, a broker acting for the holder, never had that key and
/// is not.
/// </remarks>
internal static class SubjectTokenBinding
{
    /// <summary>
    /// The DPoP key thumbprint and the certificate thumbprint <paramref name="requester"/> must prove to exchange
    /// <paramref name="subject"/>: the subject_token's own when the requester is the client it was issued to, none
    /// otherwise.
    /// </summary>
    /// <param name="subject">What the resolver read from the subject_token.</param>
    /// <param name="requester">The client requesting the exchange.</param>
    public static (string? ProofKeyThumbprint, string? CertificateSha256Thumbprint) RequiredOf(
        SubjectTokenContext subject,
        ClientInfo requester)
        => string.Equals(subject.OriginalClientId, requester.ClientId, StringComparison.Ordinal)
            ? (subject.ProofKeyThumbprint, subject.CertificateSha256Thumbprint)
            : (null, null);

    /// <summary>
    /// <paramref name="context"/> bound as <paramref name="subjectToken"/> is: to the DPoP key and the client certificate
    /// its confirmation names, if any.
    /// </summary>
    /// <param name="context">What the resolver read from the subject_token.</param>
    /// <param name="subjectToken">The payload of the subject_token.</param>
    public static SubjectTokenContext BoundAs(this SubjectTokenContext context, JsonWebTokenPayload subjectToken)
        => subjectToken.Confirmation is { } confirmation
            ? context with
            {
                ProofKeyThumbprint = confirmation.JwkThumbprint,
                CertificateSha256Thumbprint = confirmation.CertificateSha256Thumbprint,
            }
            : context;
}
