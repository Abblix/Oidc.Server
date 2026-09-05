// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;

/// <summary>
/// Provides metadata about supported ACR (Authentication Context Class Reference) values
/// for OpenID Connect discovery document.
/// </summary>
public interface IAcrMetadataProvider
{
	/// <summary>
	/// Lists the ACR (Authentication Context Class Reference) values supported by this provider.
	/// These values represent authentication assurance levels that can be requested and achieved.
	/// </summary>
	IEnumerable<string>? AcrValuesSupported { get; }
}
