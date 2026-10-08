// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Lifetime and reuse policy for refresh tokens issued by the token endpoint. Combines an absolute ceiling
/// with an optional sliding window so long-running sessions stay alive only while the client keeps using them.
/// </summary>
public record struct RefreshTokenOptions()
{
	/// <summary>
	/// Hard upper bound on a refresh token's lifetime, measured from the moment it was issued.
	/// The token is rejected once this period elapses, regardless of how recently it was used.
	/// </summary>
	public TimeSpan AbsoluteExpiresIn { get; init; } = TimeSpan.FromHours(8);

	/// <summary>
	/// Optional sliding window: each successful refresh extends the token's expiration by this amount,
	/// up to the absolute ceiling. Set to <c>null</c> to disable sliding behavior.
	/// </summary>
	public TimeSpan? SlidingExpiresIn { get; init; } = TimeSpan.FromHours(1);

	/// <summary>
	/// Whether a refresh token may be redeemed repeatedly until it expires, rather than rotated on each refresh.
	/// </summary>
	/// <remarks>
	/// <para>When <c>false</c>, each refresh rotates the token: the previous value is marked superseded as soon as a
	/// new one is issued, and later reuse of a superseded token revokes the whole grant (RFC 9700 section 4.14.2).
	/// When <c>true</c>, the client keeps redeeming its tokens, bound to it by its client authentication alone
	/// (RFC 6749 section 6).</para>
	/// <para>Left unset, a client that authenticates with a key (<c>private_key_jwt</c>, <c>tls_client_auth</c>,
	/// <c>self_signed_tls_client_auth</c>) reuses its refresh tokens and every other client rotates them. A key is a
	/// second thing to steal besides the token, so rotation adds nothing there and costs a client that fails to store
	/// a rotated token its session (FAPI 2.0 Security Profile section 5.3.2.1, note 1). A shared secret is the
	/// whole binding of a refresh token to its client, so a client using one keeps rotation, which detects a
	/// token leaked together with the secret.</para>
	/// </remarks>
	public bool? AllowReuse { get; init; }
}
