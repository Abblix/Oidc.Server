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

using System.Buffers.Text;

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Default <see cref="IGrantIdGenerator"/> implementation. Draws random bytes from a cryptographically
/// secure source (<see cref="System.Security.Cryptography.RandomNumberGenerator"/> via <c>CryptoRandom</c>)
/// using the byte count configured in <see cref="OidcOptions.GrantIdLength"/>, then URL-safe Base64 encodes
/// the result so the resulting <c>grant_id</c> value can travel safely through HTTP transports.
/// </summary>
public class GrantIdGenerator(IOptions<OidcOptions> options) : IGrantIdGenerator
{
	/// <summary>
	/// Produces a new <c>grant_id</c> value from cryptographically secure random bytes, sized per
	/// <see cref="OidcOptions.GrantIdLength"/> and URL-safe Base64 encoded.
	/// </summary>
	/// <returns>A URL-safe, randomly generated unique identifier for a refresh-token grant lineage.</returns>
	public string GenerateGrantId()
		=> Base64Url.EncodeToString(CryptoRandom.GetRandomBytes(options.Value.GrantIdLength));
}
