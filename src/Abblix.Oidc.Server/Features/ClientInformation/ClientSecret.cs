// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;
using System.Text.Json.Serialization;

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
	/// Names the notation of the string a settings file carries; the configuration binder also reads
	/// <see cref="Sha256Hash"/> itself from a Base64 string. Setting either member sets the hash; reading returns whatever
	/// <see cref="Sha256Hash"/> holds, so the two can never disagree.
	/// JSON leaves every alias out and carries the hash itself once: written alongside it, an alias is read
	/// after the hash and overwrites whatever was edited there. The configuration binder ignores the
	/// serializer's attributes, so binding is unaffected.
	/// </remarks>
	[JsonIgnore]
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
	[JsonIgnore]
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
	/// upper case; either case is accepted when writing. Left out of JSON for the reason given on
	/// <see cref="Sha256HashBase64"/>.
	/// </remarks>
	[JsonIgnore]
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
	[JsonIgnore]
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
	/// The secret encrypted for the client it was issued to, by the client secret encryption key of its tenant
	/// (<see cref="MultiTenancy.TenantDefinition.ClientSecretEncryption"/>), so the client configuration endpoint can
	/// return it when the client reads its registration (RFC 7592 section 3). Null for a secret issued while the tenant
	/// had no such key, and for one the host declares; a read then answers without the secret.
	/// </summary>
	/// <remarks>
	/// Never used to authenticate the client, which is verified against the hashes alone. Without the key it was
	/// encrypted with it opens to nothing.
	/// </remarks>
	public byte[]? EncryptedValue { get; init; }

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

	/// <summary>
	/// Keeps secret material out of the generated <see cref="object.ToString"/>, which structured
	/// logging and debugger displays reach for. A record prints every property it declares, so adding
	/// the string aliases above would otherwise have put a hash into logs in a form an attacker can
	/// take offline. Only whether a hash is present is printed, never its value.
	/// </summary>
	protected virtual bool PrintMembers(StringBuilder builder)
	{
		builder.Append("Sha256Hash = ").Append(Sha256Hash is null ? "none" : "set");
		builder.Append(", Sha512Hash = ").Append(Sha512Hash is null ? "none" : "set");
		builder.Append(", Value = ").Append(Value is null ? "none" : "set");
		builder.Append(", EncryptedValue = ").Append(EncryptedValue is null ? "none" : "set");
		builder.Append(", ExpiresAt = ").Append(ExpiresAt);
		return true;
	}
}
