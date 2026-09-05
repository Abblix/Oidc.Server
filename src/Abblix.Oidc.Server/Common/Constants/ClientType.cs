// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Enumeration representing the type of OAuth 2.0 client.
/// </summary>
public enum ClientType
{
	/// <summary>
	/// Represents a public client that does not have a client secret.
	/// </summary>
	Public,

	/// <summary>
	/// Represents a confidential client that has a client secret.
	/// </summary>
	Confidential,
}
