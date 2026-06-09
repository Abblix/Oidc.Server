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
	/// When <c>true</c>, a refresh token may be redeemed multiple times until it expires. When <c>false</c>,
	/// each refresh rotates the token: the previous value is invalidated as soon as a new one is issued.
	/// </summary>
	public bool AllowReuse { get; init; } = true;
}
