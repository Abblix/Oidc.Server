// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Serializes a <see cref="JsonWebToken"/> minted by the authorization server itself (access tokens, refresh
/// tokens, registration access tokens, initial access tokens) into a compact JWS form (RFC 7515) using the
/// server's signing keys, and - per an explicit <see cref="ServiceJwtEncryption"/> policy - optionally wraps
/// the result in a JWE (RFC 7516) encrypted to the server's own encryption key.
/// </summary>
public interface IAuthServiceJwtFormatter
{
    /// <summary>
    /// Formats and signs a JWT for use within the authentication service, applying cryptographic operations such as
    /// signing and optionally encrypting the token based on the specified requirements.
    /// </summary>
    /// <param name="token">The JSON Web Token (JWT) to be formatted and signed, potentially also encrypted.</param>
    /// <returns>A task representing the asynchronous operation, which results in the JWT formatted as a string.
    /// </returns>
    [Obsolete("Use FormatAsync(JsonWebToken, ServiceJwtEncryption) with an explicit encryption policy. " +
              "This overload encrypts implicitly whenever any service encryption key exists and is kept for " +
              "backward compatibility.")]
    Task<string> FormatAsync(JsonWebToken token);

    /// <summary>
    /// Formats and signs a JWT for use within the authentication service, and - per the supplied
    /// <paramref name="encryption"/> policy - optionally encrypts it as a JWE to the server's own encryption key.
    /// The signing algorithm and pinned signing key id come from the token header, set by the issuing service.
    /// </summary>
    /// <param name="token">The JSON Web Token (JWT) to be formatted and signed, potentially also encrypted.</param>
    /// <param name="encryption">The encryption policy: whether to encrypt, which key-management algorithm and
    /// encryption key to use, and the content-encryption algorithm.</param>
    /// <returns>A task representing the asynchronous operation, which results in the JWT formatted as a string.
    /// </returns>
    Task<string> FormatAsync(JsonWebToken token, ServiceJwtEncryption encryption);
}
