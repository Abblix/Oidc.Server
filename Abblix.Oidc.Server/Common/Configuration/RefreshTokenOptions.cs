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
/// Contains the refresh token options.
/// </summary>
public record struct RefreshTokenOptions()
{
	/// <summary>
	/// Sets the absolute period of expiration for refresh tokens.
	/// </summary>
	public TimeSpan AbsoluteExpiresIn { get; init; } = TimeSpan.FromHours(8);

	/// <summary>
	/// Sets the sliding (call-to-call relative) period of expiration for refresh tokens.
	/// </summary>
	public TimeSpan? SlidingExpiresIn { get; init; } = TimeSpan.FromHours(1);

	/// <summary>
	/// Allows to reuse refresh tokens after the first usage.
	/// </summary>
	public bool AllowReuse { get; init; } = true;
}
