// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Security.Cryptography;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.UserInfo.Validation;

/// <summary>
/// Resource-server-side enforcement of RFC 8705 §3 mutual-TLS certificate-bound access tokens
/// at the UserInfo endpoint. Mirrors the role of <see cref="DPoPUserInfoValidator"/> for the
/// <c>cnf.x5t#S256</c> binding: when the access token is certificate-bound, the SHA-256
/// thumbprint of the certificate presented on the mutual-TLS connection MUST match the bound
/// value, otherwise the request is rejected with <c>invalid_token</c> (HTTP 401, per RFC 6750).
/// </summary>
public class MtlsUserInfoValidator : IMtlsUserInfoValidator
{
    /// <inheritdoc/>
    public OidcError? Validate(ClientRequest clientRequest, JsonWebToken accessToken)
    {
        if (accessToken.Payload.Confirmation?.CertificateSha256Thumbprint is not { } committed)
        {
            // Not certificate-bound (no cnf.x5t#S256). Bearer / DPoP-only tokens are handled
            // by their own paths; nothing to enforce here.
            return null;
        }

        if (clientRequest.ClientCertificate is not { } certificate)
        {
            return new OidcError(
                ErrorCodes.InvalidToken,
                "The access token is certificate-bound (cnf.x5t#S256) but no client certificate " +
                "was presented on the mutual-TLS connection.");
        }

        // RFC 8705 §3.1: cnf.x5t#S256 is the base64url-encoded SHA-256 digest of the DER
        // encoding of the certificate, with trailing '=' padding removed.
        var presented = Base64Url.EncodeToString(SHA256.HashData(certificate.RawData));
        if (!string.Equals(presented, committed, StringComparison.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidToken,
                "The presented client certificate does not match the access token's " +
                "cnf.x5t#S256 binding.");
        }

        return null;
    }
}
