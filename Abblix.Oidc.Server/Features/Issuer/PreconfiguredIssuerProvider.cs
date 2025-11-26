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
