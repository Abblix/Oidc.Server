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

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Subtype of <see cref="OidcError"/> that signals an RFC 9449 §8 nonce-challenge: the DPoP proof either omitted
/// the <c>nonce</c> claim or carried a stale one, and the server is responding with <c>use_dpop_nonce</c> plus
/// a fresh nonce the client must echo on the next attempt. The carried <see cref="Nonce"/> value travels out through
/// the response formatter as the <c>DPoP-Nonce</c> HTTP header alongside the standard error envelope - the body
/// shape stays <c>{error, error_description}</c>; the nonce rides on a header, not in the JSON.
/// </summary>
/// <param name="Nonce">The fresh nonce the client should attach to the next DPoP proof.
/// </param>
public sealed record UseDPoPNonceError(string Nonce)
    : OidcError(ErrorCodes.UseDPoPNonce, "DPoP proof requires a fresh nonce.");
