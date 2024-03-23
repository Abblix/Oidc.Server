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

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Encapsulates the details of a client secret used in OAuth2 and OpenID Connect authentication flows.
/// </summary>
/// <remarks>
/// Client secrets are critical for the security of client applications, especially those that
/// authenticate in a server-side context. This record stores hashed versions of the secret
/// to enhance security by avoiding the storage of plain-text secrets.
/// </remarks>
public record ClientSecret
{
	/// <summary>
	/// The SHA-256 hash of the client secret. This property is used to securely store
	/// and verify the secret without needing to store the plain text value.
	/// </summary>
	/// <remarks>
	/// The SHA-256 hash provides a secure way to handle client secrets, allowing
	/// for their verification during the authentication process without risking exposure.
	/// </remarks>
	public byte[]? Sha256Hash { get; init; }

	/// <summary>
	/// The SHA-512 hash of the client secret. This property offers an additional layer
	/// of security by using a stronger hashing algorithm compared to SHA-256.
	/// </summary>
	/// <remarks>
	/// SHA-512 hashes are more resistant to brute-force attacks due to their larger size
	/// and complexity. This property is optional and can be used in systems requiring
	/// heightened security measures.
	/// </remarks>
	public byte[]? Sha512Hash { get; init; }

	/// <summary>
	/// The expiration date and time for the client secret. Secrets past this date are considered
	/// invalid and cannot be used for authentication.
	/// </summary>
	/// <remarks>
	/// Setting an expiration date for client secrets is a best practice that helps mitigate
	/// the risk of secret compromise over time. It encourages regular rotation of secrets
	/// to maintain the security integrity of client applications.
	/// </remarks>
	public DateTimeOffset? ExpiresAt { get; init; }
}
