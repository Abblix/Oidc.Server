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

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Serializes a JWT addressed to a specific client (ID Token, Logout Token, etc.) into compact
/// form: signed as a JWS (RFC 7515) with the server's signing key chosen by the JWT's header
/// algorithm, then optionally wrapped in a JWE (RFC 7516) encrypted to the client's registered
/// public key per the client's <c>id_token_encrypted_response_alg</c>/<c>_enc</c> metadata.
/// </summary>
public interface IClientJwtFormatter
{
    /// <summary>
    /// Formats a JWT for a client, inferring the encryption metadata from the token's header <c>typ</c>.
    /// </summary>
    /// <param name="token">The JWT token to format.</param>
    /// <param name="clientInfo">The client information.</param>
    /// <returns>The formatted JWT string.</returns>
    [Obsolete("Use FormatAsync(JsonWebToken, ClientInfo, ClientJwtEncryption) with an explicit " +
              "encryption policy. This overload infers the policy from token.Header.Type and is kept for backward " +
              "compatibility.")]
    Task<string> FormatAsync(JsonWebToken token, ClientInfo clientInfo);

    /// <summary>
    /// Formats a JWT for a client, signing it with the authentication service's key chosen by the token's header
    /// algorithm and - per the supplied <paramref name="encryption"/> policy - optionally encrypting it to the
    /// client's registered public key.
    /// </summary>
    /// <param name="token">The JWT token to format.</param>
    /// <param name="clientInfo">The client information.</param>
    /// <param name="encryption">The encryption policy governing whether and how the JWT is encrypted.</param>
    /// <returns>The formatted JWT string.</returns>
    Task<string> FormatAsync(JsonWebToken token, ClientInfo clientInfo, ClientJwtEncryption encryption);
}
