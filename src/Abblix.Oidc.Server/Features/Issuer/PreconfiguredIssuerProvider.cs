// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// Provides the issuer identifier for tokens based on preconfigured options in the OpenID Connect (OIDC) configuration.
/// This provider retrieves the issuer identifier from the OIDC options, making it ideal for scenarios where the issuer
/// needs to be consistent and predefined, such as environments with multiple hosts.
/// </summary>
internal class PreconfiguredIssuerProvider(IOptions<OidcOptions> options) : IIssuerProvider
{
	/// <summary>
	/// Retrieves the issuer identifier from the OIDC options.
	/// </summary>
	/// <returns>The identifier of the issuer as configured in OIDC options.</returns>
	/// <exception cref="InvalidOperationException">
	/// Thrown if the issuer identifier is not configured in OIDC options.
	/// </exception>
	public string GetIssuer() => options.Value.Issuer.NotNull(nameof(OidcOptions.Issuer));
}
