// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Interfaces;

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// Dynamically determines the issuer identifier based on the incoming HTTP request.
/// This approach allows the issuer identifier to reflect the actual request's context,
/// accommodating scenarios like varying host names or different environments.
/// </summary>
internal class RequestBasedIssuerProvider(IRequestInfoProvider requestInfoProvider) : IIssuerProvider
{
	/// <summary>
	/// Retrieves the issuer identifier based on the current HTTP request.
	/// </summary>
	/// <returns>The issuer identifier, constructed from the request's context.</returns>
	public string GetIssuer() => requestInfoProvider.ApplicationUri;
}
