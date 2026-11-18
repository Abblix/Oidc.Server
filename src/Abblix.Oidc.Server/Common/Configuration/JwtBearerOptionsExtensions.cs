// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Reads the JWT Bearer settings the way every check of a bearer assertion has to.
/// </summary>
public static class JwtBearerOptionsExtensions
{
	/// <summary>
	/// The tolerance actually applied to a bearer assertion: what this deployment set, or what the
	/// profile in force supplies.
	/// </summary>
	/// <remarks>
	/// Every reader of the setting goes through here. Three readers each applying their own
	/// fallback are three chances to disagree about what an absent value meant, and the
	/// disagreement would surface as one check refusing an assertion another had just accepted.
	/// </remarks>
	/// <param name="options">The JWT Bearer settings.</param>
	/// <param name="requirements">The control bundle in force, which a per-client caller resolves from the
	/// client's own profile.</param>
	public static ClockSkew ResolveClockSkew(this JwtBearerOptions options, SecurityProfileRequirements requirements)
		=> requirements.ClockSkewOrDefault(options.ClockSkew);
}
