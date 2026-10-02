// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Frozen;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using static System.Globalization.CultureInfo;
using static System.Globalization.DateTimeStyles;
using static System.Globalization.NumberStyles;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Carries a JSON value through a claim and back, keeping its exact JSON kind and CLR type: the claim's
/// <see cref="Claim.ValueType"/> is the only channel that survives the claim being serialized into the
/// authentication cookie, so it records which kind was written.
/// </summary>
internal static class JsonClaimValue
{
	/// <summary>
	/// Claim <see cref="Claim.ValueType"/> markers for the JSON node kinds the standard <see cref="ClaimValueTypes"/>
	/// set does not distinguish.
	/// </summary>
	private static class CustomValueTypes
	{
		/// <summary>
		/// A JSON object, serialized to its JSON text. Matches <c>JsonClaimValueTypes.Json</c> of
		/// System.IdentityModel.Tokens.Jwt / Microsoft.IdentityModel, declared here by value
		/// so claims interoperate with JWT handlers without taking a dependency on those packages.
		/// </summary>
		public const string Json = "JSON";

		/// <summary>
		/// A JSON array, serialized to its JSON text. Matches <c>JsonClaimValueTypes.JsonArray</c> of
		/// System.IdentityModel.Tokens.Jwt / Microsoft.IdentityModel.
		/// </summary>
		public const string JsonArray = "JSON_ARRAY";

		/// <summary>
		/// A single-precision floating-point value - the <c>xs:float</c> XSD primitive type URI, a sibling of
		/// <c>ClaimValueTypes.Double</c> = <c>xs:double</c>.
		/// </summary>
		public const string Float = "http://www.w3.org/2001/XMLSchema#float";

		/// <summary>
		/// A decimal value - the <c>xs:decimal</c> XSD primitive type URI, a sibling of
		/// <c>ClaimValueTypes.Double</c> = <c>xs:double</c>.
		/// </summary>
		public const string Decimal = "http://www.w3.org/2001/XMLSchema#decimal";

		/// <summary>
		/// A <c>DateTimeOffset</c> - it has no XSD primitive distinct from <c>xs:dateTime</c> (which
		/// <c>ClaimValueTypes.DateTime</c> already uses for a <c>DateTime</c>), so it keeps a library-specific marker.
		/// </summary>
		public const string DateTimeOffset = "urn:abblix:datetimeoffset";
	}

	/// <summary>
	/// The primitive kinds, tried in this order when writing - a Chain of Responsibility in which the first kind the
	/// value converts to wins. The order matters: string and bool first, then integers widest-last, then the floating
	/// kinds, each tagged distinctly so the read side reconstructs the exact CLR/JSON type.
	/// </summary>
	/// <remarks>
	/// Dates use the ISO 8601 round-trip format ("O") with full precision. DateTime and DateTimeOffset are tagged
	/// distinctly so the read side rebuilds the same CLR type: a DateTime keeps its Kind, a DateTimeOffset keeps its
	/// offset, neither is silently coerced into the other (which would otherwise bake in the server's local offset).
	/// </remarks>
	private static readonly PrimitiveClaimFormat[] PrimitiveFormats =
	[
		new(ClaimValueTypes.String, WriteString, ReadString),
		new(ClaimValueTypes.Boolean, WriteBoolean, ReadBoolean),
		new(ClaimValueTypes.Integer32, WriteInt32, ReadInt32),
		new(ClaimValueTypes.Integer64, WriteInt64, ReadInt64),
		new(CustomValueTypes.Float, WriteFloat, ReadFloat),
		new(ClaimValueTypes.Double, WriteDouble, ReadDouble),
		new(CustomValueTypes.Decimal, WriteDecimal, ReadDecimal),
		new(ClaimValueTypes.DateTime, WriteDateTime, ReadDateTime),
		new(CustomValueTypes.DateTimeOffset, WriteDateTimeOffset, ReadDateTimeOffset),
	];

	private static readonly FrozenDictionary<string, PrimitiveClaimFormat> FormatsByValueType =
		PrimitiveFormats.ToFrozenDictionary(format => format.ValueType, StringComparer.Ordinal);

	/// <summary>
	/// Creates a claim from a JSON value. Primitives are converted to their string representation with a value type
	/// that pins the exact JSON kind; arrays and objects are JSON-serialized and tagged so the read side parses them
	/// back rather than handing back the serialized string.
	/// </summary>
	public static Claim ToClaim(string claimType, JsonNode claimValue) => claimValue switch
	{
		JsonArray => new Claim(claimType, claimValue.ToJsonString(), CustomValueTypes.JsonArray),

		JsonValue primitive when Format(primitive) is { } formatted
			=> new Claim(claimType, formatted.Text, formatted.ValueType),

		// Objects, and any JsonValue of a kind no primitive format takes.
		_ => new Claim(claimType, claimValue.ToJsonString(), CustomValueTypes.Json),
	};

	/// <summary>
	/// Parses a claim back to a JSON value using the claim's value type to reconstruct the exact type
	/// <see cref="ToClaim"/> recorded.
	/// </summary>
	public static JsonNode? FromClaim(Claim claim)
	{
		var value = claim.Value;

		if (string.IsNullOrEmpty(value))
			return null;

		// A primitive whose text does not parse as its recorded kind is still the value it was given, so it is kept
		// as a string. The JSON markers, or a claim written by something other than ToClaim, are tried as JSON.
		return FormatsByValueType.TryGetValue(claim.ValueType, out var format)
			? format.Read(value) ?? JsonValue.Create(value)
			: ParseJsonOrString(value);
	}

	private static (string Text, string ValueType)? Format(JsonValue value)
	{
		foreach (var format in PrimitiveFormats)
		{
			if (format.Write(value) is { } text)
				return (text, format.ValueType);
		}

		return null;
	}

	private static string? WriteString(JsonValue value)
		=> value.TryGetValue<string>(out var text) ? text : null;

	private static JsonNode? ReadString(string text) => JsonValue.Create(text);

	private static string? WriteBoolean(JsonValue value)
		=> value.TryGetValue<bool>(out var flag) ? flag.ToString().ToLowerInvariant() : null;

	private static JsonNode? ReadBoolean(string text)
		=> bool.TryParse(text, out var flag) ? JsonValue.Create(flag) : null;

	private static string? WriteInt32(JsonValue value)
		=> value.TryGetValue<int>(out var number) ? number.ToString(InvariantCulture) : null;

	private static JsonNode? ReadInt32(string text)
		=> int.TryParse(text, Integer, InvariantCulture, out var number) ? JsonValue.Create(number) : null;

	private static string? WriteInt64(JsonValue value)
		=> value.TryGetValue<long>(out var number) ? number.ToString(InvariantCulture) : null;

	private static JsonNode? ReadInt64(string text)
		=> long.TryParse(text, Integer, InvariantCulture, out var number) ? JsonValue.Create(number) : null;

	private static string? WriteFloat(JsonValue value)
		=> value.TryGetValue<float>(out var number)
			? Exactly(value, number.ToString(InvariantCulture), float.IsFinite(number))
			: null;

	private static JsonNode? ReadFloat(string text)
		=> float.TryParse(text, Float, InvariantCulture, out var number) ? JsonValue.Create(number) : null;

	private static string? WriteDouble(JsonValue value)
		=> value.TryGetValue<double>(out var number)
			? Exactly(value, number.ToString(InvariantCulture), double.IsFinite(number))
			: null;

	/// <summary>
	/// The text a floating kind would write for <paramref name="value"/>, or null when that kind does not hold it.
	/// </summary>
	/// <remarks>
	/// A number parsed from JSON text converts to every floating kind, rounding to its precision and overflowing to
	/// infinity past its range, so the narrowest kind tried first would keep only what it can hold. Such a number is
	/// held when the kind's value is finite - JSON has no infinity - and the text reads back as the same decimal the
	/// number reads as, where it has one. A single or double the host created is its own kind and is written as it is.
	/// </remarks>
	private static string? Exactly(JsonValue value, string text, bool finite)
		=> !value.TryGetValue<JsonElement>(out var element) || (finite && ReadsBackAs(element, text)) ? text : null;

	private static bool ReadsBackAs(JsonElement element, string text)
		=> !element.TryGetDecimal(out var exact) ||
		   (decimal.TryParse(text, Float, InvariantCulture, out var written) && written == exact);

	private static JsonNode? ReadDouble(string text)
		=> double.TryParse(text, Float, InvariantCulture, out var number) ? JsonValue.Create(number) : null;

	private static string? WriteDecimal(JsonValue value)
		=> value.TryGetValue<decimal>(out var number) ? number.ToString(InvariantCulture) : null;

	private static JsonNode? ReadDecimal(string text)
		=> decimal.TryParse(text, Float, InvariantCulture, out var number) ? JsonValue.Create(number) : null;

	// For DateTime: "2009-06-15T13:45:30.0000000" or "2009-06-15T13:45:30.0000000Z"
	private static string? WriteDateTime(JsonValue value)
		=> value.TryGetValue<DateTime>(out var instant) ? instant.ToString("O", InvariantCulture) : null;

	private static JsonNode? ReadDateTime(string text)
		=> DateTime.TryParse(text, InvariantCulture, RoundtripKind, out var instant) ? JsonValue.Create(instant) : null;

	// For DateTimeOffset: "2009-06-15T13:45:30.0000000-07:00"
	private static string? WriteDateTimeOffset(JsonValue value)
		=> value.TryGetValue<DateTimeOffset>(out var instant) ? instant.ToString("O", InvariantCulture) : null;

	private static JsonNode? ReadDateTimeOffset(string text)
		=> DateTimeOffset.TryParse(text, InvariantCulture, RoundtripKind, out var instant)
			? JsonValue.Create(instant)
			: null;

	private static JsonNode? ParseJsonOrString(string value)
	{
		try
		{
			return JsonNode.Parse(value) ?? JsonValue.Create(value);
		}
		catch (JsonException)
		{
			return JsonValue.Create(value);
		}
	}
}
