// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.UriValidation;

/// <summary>
/// Decides whether a URI received from a client is acceptable for a given OAuth/OIDC use,
/// most commonly the redirect URI matching rules of RFC 6749 section 3.1.2 and the loopback /
/// custom-scheme accommodations of RFC 8252 (OAuth 2.0 for Native Apps).
/// </summary>
public interface IUriValidator
{
	/// <summary>
	/// Validates the specified URI against predefined rules.
	/// </summary>
	/// <param name="uri">The URI to validate.</param>
	/// <returns><c>true</c> if the URI meets the validation criteria; otherwise, <c>false</c>.</returns>
	bool IsValid(Uri uri);
}
