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

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Encapsulates the details of a client secret used in OAuth2 and OpenID Connect authentication flows.
/// </summary>
/// <remarks>
/// Client secrets are critical for the security of client applications, especially those that
/// authenticate in a server-side context. This record stores hashed versions of the secret
/// to enhance security by avoiding the storage of plain-text secrets. For client_secret_jwt
/// authentication method, the raw value must also be stored to validate HMAC-signed JWTs.
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
	/// <see cref="Sha256Hash"/> written as a single Base64 string, for a registry that lives in
	/// configuration.
	/// </summary>
	/// <remarks>
	/// The .NET configuration binder treats a byte array as a collection to fill element by element,
	/// so a hash has no scalar form to bind to without this alias: a settings file would have to spell
	/// the value out one byte per key. Setting either member sets the hash; reading returns whatever
	/// <see cref="Sha256Hash"/> holds, so the two can never disagree.
	/// </remarks>
	public string? Sha256HashBase64
	{
		get => Sha256Hash is { } hash ? Convert.ToBase64String(hash) : null;
		init => Sha256Hash = value is null ? null : Convert.FromBase64String(value);
	}

	/// <summary>
	/// <see cref="Sha512Hash"/> written as a single Base64 string, for a registry that lives in
	/// configuration.
	/// </summary>
	/// <inheritdoc cref="Sha256HashBase64" path="/remarks"/>
	public string? Sha512HashBase64
	{
		get => Sha512Hash is { } hash ? Convert.ToBase64String(hash) : null;
		init => Sha512Hash = value is null ? null : Convert.FromBase64String(value);
	}

	/// <summary>
	/// <see cref="Sha256Hash"/> written as a single hexadecimal string, which is the form command-line
	/// digest tools print and the form most people paste.
	/// </summary>
	/// <remarks>
	/// The same alias as <see cref="Sha256HashBase64"/> in the other common notation. Reading returns
	/// upper case; either case is accepted when writing.
	/// </remarks>
	public string? Sha256HashHex
	{
		get => Sha256Hash is { } hash ? Convert.ToHexString(hash) : null;
		init => Sha256Hash = value is null ? null : Convert.FromHexString(value);
	}

	/// <summary>
	/// <see cref="Sha512Hash"/> written as a single hexadecimal string, which is the form command-line
	/// digest tools print and the form most people paste.
	/// </summary>
	/// <inheritdoc cref="Sha256HashHex" path="/remarks"/>
	public string? Sha512HashHex
	{
		get => Sha512Hash is { } hash ? Convert.ToHexString(hash) : null;
		init => Sha512Hash = value is null ? null : Convert.FromHexString(value);
	}

	/// <summary>
	/// The plain-text value of the client secret. This property is required for authentication methods
	/// that need the raw secret value, such as client_secret_jwt (which uses HMAC signatures).
	/// </summary>
	/// <remarks>
	/// While storing plain-text secrets poses security risks, some authentication methods like
	/// client_secret_jwt require access to the original value to create HMAC signatures for validation.
	/// This value should be stored securely and access should be restricted.
	/// </remarks>
	public string? Value { get; init; }

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
