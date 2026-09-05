// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Represents subject types used in OpenID Connect.
/// </summary>
public static class SubjectTypes
{
	/// <summary>
	/// The "public" subject type indicates that the subject identifier is a public identifier,
	/// which means that it can be used across multiple clients and should not be tied to a specific client.
	/// </summary>
	public const string Public = "public";

	/// <summary>
	/// The "pairwise" subject type indicates that the subject identifier is a pairwise identifier,
	/// which means that it is unique to a specific client, enhancing user privacy.
	/// </summary>
	public const string Pairwise = "pairwise";
}
