// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Abblix.Jwt;

/// <summary>
/// Represents the payload part of a JSON Web Token (JWT), containing the claims or statements about the subject.
/// </summary>
/// <remarks>
/// The JWT payload is a JSON object that contains the claims transmitted by the token. Standard claims
/// such as issuer, subject, expiration time, and more can be included, as well as additional claims as needed.
/// This class provides a convenient way to work with the payload, allowing for easy access and modification of claims.
/// </remarks>
public class JsonWebTokenPayload(JsonObject json)
{
	/// <summary>
	/// The underlying mutable JSON object backing the strongly-typed accessors on this payload.
	/// Use this for custom claims that are not exposed as named properties on this class.
	/// </summary>
	public JsonObject Json { get; } = json;

	/// <summary>
	/// Indexer to get or set claim values in the payload using the claim name.
	/// </summary>
	/// <param name="name">The name of the claim.</param>
	/// <returns>The value of the claim if it exists; otherwise, null.</returns>
	public JsonNode? this[string name] {
		get => Json[name];
		set => Json.SetProperty(name, value);
	}

	/// <summary>
	/// The unique identifier of the JWT.
	/// </summary>
	public string? JwtId
	{
		get => Json.GetProperty<string>(JwtClaimTypes.JwtId);
		set => Json.SetProperty(JwtClaimTypes.JwtId, value);
	}

	/// <summary>
	/// The time at which the JWT was issued, represented as a Unix timestamp.
	/// </summary>
	public DateTimeOffset? IssuedAt
	{
		get => Json.GetUnixTimeSeconds(JwtClaimTypes.IssuedAt);
		set => Json.SetUnixTimeSeconds(JwtClaimTypes.IssuedAt, value);
	}

	/// <summary>
	/// The time before which the JWT must not be accepted for processing, represented as a Unix timestamp.
	/// </summary>
	public DateTimeOffset? NotBefore
	{
		get => Json.GetUnixTimeSeconds(JwtClaimTypes.NotBefore);
		set => Json.SetUnixTimeSeconds(JwtClaimTypes.NotBefore, value);
	}

	/// <summary>
	/// The expiration time on or after which the JWT must not be accepted for processing, represented as a Unix timestamp.
	/// </summary>
	public DateTimeOffset? ExpiresAt
	{
		get => Json.GetUnixTimeSeconds(JwtClaimTypes.ExpiresAt);
		set => Json.SetUnixTimeSeconds(JwtClaimTypes.ExpiresAt, value);
	}

	/// <summary>
	/// Reads the three timestamp claims at once, answering false with the reason instead of throwing
	/// where one of them cannot be read.
	/// </summary>
	/// <remarks>
	/// The typed accessors throw on a value that is not a NumericDate - a string, an object, a number
	/// outside the range <see cref="DateTimeOffset"/> can hold - because a caller asking for a
	/// timestamp has nowhere to put "the token lied". A validator does: a claim it cannot read is a
	/// refusal of the token, never an exception out of the request. This is the read a validator
	/// makes, and it names the claim, since the sender can fix only the one it is told about.
	/// </remarks>
	/// <param name="notBefore">The <c>nbf</c> claim, or null where the token carries none.</param>
	/// <param name="expiresAt">The <c>exp</c> claim, or null where the token carries none.</param>
	/// <param name="issuedAt">The <c>iat</c> claim, or null where the token carries none.</param>
	/// <param name="whyUnreadable">Which claim could not be read and what it held, or null where all three were read.</param>
	/// <returns>True where every timestamp the token carries was read.</returns>
	public bool TryReadTimestamps(
		out DateTimeOffset? notBefore,
		out DateTimeOffset? expiresAt,
		out DateTimeOffset? issuedAt,
		[NotNullWhen(false)] out string? whyUnreadable)
	{
		notBefore = expiresAt = issuedAt = null;

		return TryReadTimestamp(JwtClaimTypes.NotBefore, out notBefore, out whyUnreadable)
		       && TryReadTimestamp(JwtClaimTypes.ExpiresAt, out expiresAt, out whyUnreadable)
		       && TryReadTimestamp(JwtClaimTypes.IssuedAt, out issuedAt, out whyUnreadable);
	}

	/// <summary>
	/// Reads one timestamp claim by name, answering false with the reason instead of throwing where
	/// it cannot be read.
	/// </summary>
	/// <remarks>
	/// For a caller that judges one claim and must say nothing about the others: a DPoP proof is
	/// refused on its <c>iat</c> alone, and a refusal naming a claim it never looked at would be
	/// wrong twice over.
	/// </remarks>
	/// <param name="claim">The claim name, one of the registered timestamp claims or any other
	/// claim holding a NumericDate.</param>
	/// <param name="value">The claim's value, or null where the token carries none.</param>
	/// <param name="whyUnreadable">Which claim could not be read and what it held, or null where it was read.</param>
	/// <returns>True where the claim was read, or is absent.</returns>
	public bool TryReadTimestamp(string claim, out DateTimeOffset? value, [NotNullWhen(false)] out string? whyUnreadable)
	{
		try
		{
			value = Json.GetUnixTimeSeconds(claim);
			whyUnreadable = null;
			return true;
		}
		// The reader beneath raises InvalidOperationException or JsonException for a value that is
		// not a number and ArgumentOutOfRangeException for one no date can hold, the same on every
		// runtime this package targets. FormatException is the documented failure of the numeric
		// readers this rests on, kept so a future reader change cannot turn a refusal back into an
		// exception.
		catch (Exception ex) when (ex is InvalidOperationException or JsonException or ArgumentOutOfRangeException or FormatException)
		{
			// The value is quoted back rather than described: "not a NumericDate" tells a sender
			// nothing about which of its two ways of writing a date this server meant.
			value = null;
			whyUnreadable = $"The '{claim}' claim holds {Json[claim]?.ToJsonString()}, which cannot be read as a NumericDate";
			return false;
		}
	}

	/// <summary>
	/// The issuer of the JWT.
	/// </summary>
	public string? Issuer
	{
		get => Json.GetProperty<string>(JwtClaimTypes.Issuer);
		set => Json.SetProperty(JwtClaimTypes.Issuer, value);
	}

	/// <summary>
	/// The intended audiences for the JWT.
	/// </summary>
	public IEnumerable<string> Audiences
	{
		get => Json.GetArrayOfStrings(JwtClaimTypes.Audience);
		set => Json.SetArrayOrString(JwtClaimTypes.Audience, value);
	}

	/// <summary>
	/// The subject of the JWT.
	/// The subject typically represents the principal that is the focus of the JWT, often a user identifier.
	/// </summary>
	/// <remarks>
	/// The 'sub' (subject) claim is a standard claim in JWTs used to uniquely identify the principal,
	/// usually in the context of authentication or user identity. It is commonly a user ID or username.
	/// </remarks>
	public string? Subject
	{
		get => Json.GetProperty<string>(JwtClaimTypes.Subject);
		set => Json.SetProperty(JwtClaimTypes.Subject, value);
	}

	/// <summary>
	/// The proof-of-possession confirmation object (RFC 7800 section 3.1 <c>cnf</c>) bound to this
	/// JWT. Carries each binding the token holds - <c>cnf.x5t#S256</c> for mTLS-bound
	/// tokens (RFC 8705 section 3.1) and <c>cnf.jkt</c> for DPoP-bound tokens (RFC 9449 section 6.1) -
	/// behind typed accessors. Assignment writes the wrapped <see cref="JsonObject"/> as
	/// the <c>cnf</c> claim; assigning <c>null</c> removes the claim.
	/// </summary>
	public JsonWebTokenConfirmation? Confirmation
	{
		get => Json[IanaClaimTypes.Cnf] is JsonObject obj ? new JsonWebTokenConfirmation(obj) : null;
		set => Json.SetProperty(IanaClaimTypes.Cnf, value?.Json);
	}

}
