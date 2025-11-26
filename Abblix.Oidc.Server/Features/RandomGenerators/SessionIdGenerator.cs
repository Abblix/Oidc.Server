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

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Implements the <see cref="ISessionIdGenerator"/> interface to generate unique session identifiers.
/// The session IDs are generated using a cryptographically strong random number generator and are encoded
/// to be safely included in HTTP URLs, avoiding characters that might cause issues in URLs.
/// </summary>
public class SessionIdGenerator(IOptions<OidcOptions> options) : ISessionIdGenerator
{
	/// <summary>
	/// Generates a new session identifier. The method employs a cryptographically strong random number generator
	/// to produce a sequence of bytes, which are then URL-encoded to ensure they can be safely used within HTTP URLs.
	/// This approach ensures that the session identifiers are highly unlikely to collide and are secure for use in
	/// web applications.
	/// </summary>
	/// <returns>A string representing a URL-safe, cryptographically strong random session identifier. The identifier
	/// is encoded in a way that makes it suitable for use in HTTP URLs, cookies, or any other URL-based contexts.</returns>
	public string GenerateSessionId()
		=> HttpServerUtility.UrlTokenEncode(CryptoRandom.GetRandomBytes(options.Value.SessionIdLength));
}
