// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Produces unique identifiers for JSON Web Tokens, used as the <c>jti</c> claim defined in RFC 7519 §4.1.7.
/// A unique <c>jti</c> per token is required to support replay detection and one-time token semantics, so
/// implementations must generate values with sufficient entropy to make collisions and guessing impractical.
/// </summary>
public interface ITokenIdGenerator
{
	/// <summary>
	/// Generates a new unique identifier suitable for the <c>jti</c> claim of a JWT.
	/// </summary>
	/// <returns>A unique identifier suitable for use as a JWT ID.</returns>
	string GenerateTokenId();
}
