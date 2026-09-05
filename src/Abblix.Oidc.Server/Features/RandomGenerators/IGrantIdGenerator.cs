// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Produces unique identifiers for refresh-token grants, used as the <c>grant_id</c> claim that binds every
/// refresh token derived from one authorization grant into a single lineage (a "token family" in RFC 9700
/// terms). Rotation and family revocation (RFC 9700 §4.14.2) rely on this identifier, so implementations must
/// generate values with sufficient entropy to make collisions and guessing impractical.
/// </summary>
public interface IGrantIdGenerator
{
	/// <summary>
	/// Generates a new unique identifier suitable for the <c>grant_id</c> claim of a refresh token.
	/// </summary>
	/// <returns>A unique identifier for a refresh-token grant lineage.</returns>
	string GenerateGrantId();
}
