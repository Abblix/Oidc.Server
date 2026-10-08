// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// When a refresh token may be redeemed repeatedly until it expires, rather than rotated on each refresh.
/// </summary>
public enum RefreshTokenReusePolicy
{
	/// <summary>
	/// Refresh tokens are reused only by a client that authenticates by certificate (<c>tls_client_auth</c>,
	/// <c>self_signed_tls_client_auth</c>) or with <c>private_key_jwt</c> while requiring DPoP. Every other client
	/// rotates them.
	/// </summary>
	/// <remarks>
	/// Rotation adds nothing for a confidential client whose access tokens are sender-constrained, and costs a client
	/// that fails to store a rotated token its session (FAPI 2.0 Security Profile section 5.3.2.1, note 1). Both
	/// conditions are required on every request, not merely allowed: a certificate authenticates each request and
	/// binds its token, and a client requiring DPoP is refused without a proof. A <c>private_key_jwt</c> client whose
	/// certificate binding is optional rotates, since a request made without a certificate gets an unbound token. A
	/// client using a shared secret rotates as well: the server stores that secret, so a leak of the client store
	/// hands it out together with the tokens, while a private key never reaches the server.
	/// </remarks>
	WhenSenderConstrained,

	/// <summary>
	/// The client keeps redeeming its refresh tokens, bound to it by its client authentication alone
	/// (RFC 6749 section 6).
	/// </summary>
	Reuse,

	/// <summary>
	/// Each refresh rotates the token: the previous value is marked superseded as soon as a new one is issued, and a
	/// later presentation of a superseded token revokes the whole grant (RFC 9700 section 4.14.2).
	/// </summary>
	Rotate,
}
