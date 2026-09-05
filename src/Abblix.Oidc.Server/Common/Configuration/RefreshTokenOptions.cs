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
	/// When <c>false</c> (the secure default), each refresh rotates the token: the previous value is marked
	/// superseded as soon as a new one is issued, and later reuse of a superseded token revokes the whole
	/// token family (RFC 9700 Section 4.14.2). Set to <c>true</c> to opt a client into multi-use refresh
	/// tokens that may be redeemed repeatedly until they expire - appropriate only for confidential clients
	/// whose client authentication already binds the token to its identity (RFC 6749).
	/// </summary>
	public bool AllowReuse { get; init; } = false;
}
