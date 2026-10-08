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
	/// When a refresh token may be redeemed repeatedly until it expires, rather than rotated on each refresh.
	/// </summary>
	/// <remarks>
	/// A security profile that forbids rotation, as FAPI 2.0 does, decides over this policy, so a client held to such
	/// a profile reuses its refresh tokens even with <see cref="RefreshTokenReusePolicy.Rotate"/>.
	/// </remarks>
	public RefreshTokenReusePolicy ReusePolicy { get; init; }
}
