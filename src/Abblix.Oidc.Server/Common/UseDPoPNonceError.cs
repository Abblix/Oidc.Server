// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
