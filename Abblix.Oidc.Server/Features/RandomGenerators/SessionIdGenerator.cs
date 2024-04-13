// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Implements the <see cref="ISessionIdGenerator"/> interface to generate unique session identifiers.
/// The session IDs are generated using a cryptographically strong random number generator and are encoded
/// to be safely included in HTTP URLs, avoiding characters that might cause issues in URLs.
/// </summary>
public class SessionIdGenerator : ISessionIdGenerator
{
	/// <summary>
	/// Generates a new session identifier. The method employs a cryptographically strong random number generator
	/// to produce a sequence of bytes, which are then URL-encoded to ensure they can be safely used within HTTP URLs.
	/// This approach ensures that the session identifiers are highly unlikely to collide and are secure for use in
	/// web applications.
	/// </summary>
	/// <returns>A string representing a URL-safe, cryptographically strong random session identifier. The identifier
	/// is encoded in a way that makes it suitable for use in HTTP URLs, cookies, or any other URL-based contexts.</returns>
	public string GenerateSessionId() => HttpServerUtility.UrlTokenEncode(CryptoRandom.GetRandomBytes(32));
}
