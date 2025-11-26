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

using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Unit tests for JWT claims serialization and deserialization (round-trip testing).
/// Tests verify that all JWT claim types correctly survive the complete cycle:
/// create → serialize → sign → encrypt → decrypt → validate → deserialize.
/// Covers primitive types, arrays, structured objects, and standard JWT/OIDC claims per RFC 7519 and OIDC Core.
/// </summary>
public class JsonWebTokenClaimsTests
{
    private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(JsonWebKeyUseNames.Sig);
    private static readonly JsonWebKey EncryptingKey = JsonWebKeyFactory.CreateRsa(JsonWebKeyUseNames.Enc);

    /// <summary>
    /// Verifies that JWT string claims round-trip correctly through sign/encrypt/decrypt/validate cycle.
    /// Tests various string types: simple, empty, Unicode, special characters, URLs, JSON-escaped strings.
    /// Per RFC 7519, string claims are stored as JSON string values in the payload.
    /// </summary>
    [Theory]
    [InlineData("simple_string", "Hello, World!")]
    [InlineData("empty_string", "")]
    [InlineData("unicode_string", "Hello 世界 🌍")]
    [InlineData("special_chars", "Test@#$%^&*()_+-={}[]|\\:\";<>?,./")]
    [InlineData("url", "https://example.com/path?query=value&foo=bar")]
    [InlineData("json_escaped", "{\"nested\":\"value\"}")]
    public async Task PlainStringClaims_RoundTrip_PreservesValues(string claimName, string claimValue)
    {
        var token = CreateToken();
        token.Payload[claimName] = claimValue;

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualValue = roundTripToken.Payload.Json.GetProperty<string>(claimName);
        Assert.Equal(claimValue, actualValue);
    }

    /// <summary>
    /// Verifies that JWT integer (int32) claims round-trip correctly.
    /// Tests edge cases: zero, negative, max/min int32 values.
    /// Per RFC 7519, numeric claims are stored as JSON numbers (no quotes).
    /// </summary>
    [Theory]
    [InlineData("int_claim", 42)]
    [InlineData("zero", 0)]
    [InlineData("negative", -123)]
    [InlineData("max_int", int.MaxValue)]
    [InlineData("min_int", int.MinValue)]
    public async Task PlainIntegerClaims_RoundTrip_PreservesValues(string claimName, int claimValue)
    {
        var token = CreateToken();
        token.Payload[claimName] = claimValue;

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualValue = roundTripToken.Payload.Json.GetProperty<int>(claimName);
        Assert.Equal(claimValue, actualValue);
    }

    /// <summary>
    /// Verifies that JWT long (int64) claims round-trip correctly.
    /// Tests edge cases: max/min int64 values, large negative numbers.
    /// Critical for handling NumericDate values (seconds since epoch) per RFC 7519 Section 2.
    /// </summary>
    [Theory]
    [InlineData("long_claim", 9223372036854775807L)]
    [InlineData("long_negative", -9223372036854775808L)]
    public async Task PlainLongClaims_RoundTrip_PreservesValues(string claimName, long claimValue)
    {
        var token = CreateToken();
        token.Payload[claimName] = claimValue;

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualValue = roundTripToken.Payload.Json.GetProperty<long>(claimName);
        Assert.Equal(claimValue, actualValue);
    }

    /// <summary>
    /// Verifies that JWT boolean claims round-trip correctly.
    /// Tests both true and false values.
    /// Per RFC 7519, boolean claims are stored as JSON boolean literals (true/false, not strings).
    /// </summary>
    [Theory]
    [InlineData("bool_true", true)]
    [InlineData("bool_false", false)]
    public async Task PlainBooleanClaims_RoundTrip_PreservesValues(string claimName, bool claimValue)
    {
        var token = CreateToken();
        token.Payload[claimName] = claimValue;

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualValue = roundTripToken.Payload.Json.GetProperty<bool>(claimName);
        Assert.Equal(claimValue, actualValue);
    }

    /// <summary>
    /// Verifies that JWT floating-point (double) claims round-trip correctly with precision tolerance.
    /// Tests positive and negative values.
    /// Note: JSON number serialization may introduce minor precision differences.
    /// </summary>
    [Theory]
    [InlineData("float_claim", 3.14159)]
    [InlineData("double_negative", -273.15)]
    public async Task PlainDoubleClaims_RoundTrip_PreservesValues(string claimName, double claimValue)
    {
        var token = CreateToken();
        token.Payload[claimName] = claimValue;

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualValue = roundTripToken.Payload.Json.GetProperty<double>(claimName);
        Assert.Equal(claimValue, actualValue, precision: 5);
    }

    /// <summary>
    /// Verifies that double value 0.0 is serialized as integer 0 (JSON optimization).
    /// Per JSON spec, 0.0 and 0 are semantically equivalent, so serializers may optimize.
    /// Tests handling of numeric type coercion during serialization.
    /// </summary>
    [Fact]
    public async Task PlainDoubleClaim_Zero_RoundTrip_BecomesInteger()
    {
        var token = CreateToken();
        token.Payload["double_zero"] = 0.0;

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualValue = roundTripToken.Payload.Json.GetProperty<int>("double_zero");
        Assert.Equal(0, actualValue);
    }

    /// <summary>
    /// Verifies that claims set to null are removed from the JWT payload.
    /// Per JSON best practice, null values are typically omitted to reduce token size.
    /// Tests claim removal optimization.
    /// </summary>
    [Fact]
    public async Task NullClaim_RoundTrip_IsRemovedFromPayload()
    {
        var token = CreateToken();
        token.Payload["test_claim"] = "value";
        token.Payload["test_claim"] = null;

        var roundTripToken = await SignEncryptAndValidate(token);

        Assert.False(roundTripToken.Payload.Json.ContainsKey("test_claim"));
    }

    /// <summary>
    /// Verifies that arrays with single value are stored as simple strings (not arrays).
    /// OAuth 2.0 / OIDC optimization: audience with one value is stored as string, not array.
    /// Per RFC 7519 Section 4.1.3, "aud" can be string or array of strings.
    /// </summary>
    [Fact]
    public async Task ArrayClaim_SingleValue_RoundTrip_PreservesAsSingleValue()
    {
        var token = CreateToken();
        var values = new[] { "single_value" };
        token.Payload.Json.SetArrayOrString("roles", values);

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualValues = roundTripToken.Payload.Json.GetArrayOfStrings("roles").ToArray();
        Assert.Equal(values, actualValues);
    }

    /// <summary>
    /// Verifies that arrays with multiple values round-trip correctly as JSON arrays.
    /// Tests typical use case: multiple roles, scopes, or audiences.
    /// Per RFC 7519, array claims are stored as JSON arrays.
    /// </summary>
    [Fact]
    public async Task ArrayClaim_MultipleValues_RoundTrip_PreservesAsArray()
    {
        var token = CreateToken();
        var values = new[] { "admin", "user", "moderator" };
        token.Payload.Json.SetArrayOrString("roles", values);

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualValues = roundTripToken.Payload.Json.GetArrayOfStrings("roles").ToArray();
        Assert.Equal(values, actualValues);
    }

    /// <summary>
    /// Verifies that empty arrays are removed from JWT payload.
    /// Optimization: empty arrays provide no information and increase token size.
    /// Tests claim removal for empty collections.
    /// </summary>
    [Fact]
    public async Task ArrayClaim_EmptyArray_RoundTrip_IsRemovedFromPayload()
    {
        var token = CreateToken();
        token.Payload.Json.SetArrayOrString("roles", []);

        var roundTripToken = await SignEncryptAndValidate(token);

        Assert.False(roundTripToken.Payload.Json.ContainsKey("roles"));
    }

    /// <summary>
    /// Verifies that array claims with special characters (colons, slashes, spaces, Unicode) preserve correctly.
    /// Tests real-world scenarios: scoped permissions, namespaced roles, internationalized values.
    /// Critical for OIDC scope claims which often contain colons and slashes.
    /// </summary>
    [Fact]
    public async Task ArrayClaim_SpecialCharacters_RoundTrip_PreservesValues()
    {
        var token = CreateToken();
        var values = new[]
        {
            "role:admin",
            "group/moderators",
            "permission:read,write",
            "scope with spaces",
            "unicode_role_世界"
        };
        token.Payload.Json.SetArrayOrString("roles", values);

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualValues = roundTripToken.Payload.Json.GetArrayOfStrings("roles").ToArray();
        Assert.Equal(values, actualValues);
    }

    /// <summary>
    /// Verifies that array claims set to null are removed from JWT payload.
    /// Tests optional array claims (e.g., amr - Authentication Methods References).
    /// Per OIDC spec, amr claim is optional and may be omitted.
    /// </summary>
    [Fact]
    public async Task ArrayClaimOrNull_NullValue_RoundTrip_IsRemovedFromPayload()
    {
        var token = CreateToken();
        token.Payload.Json.SetArrayOrStringOrNull("amr", null);

        var roundTripToken = await SignEncryptAndValidate(token);

        Assert.False(roundTripToken.Payload.Json.ContainsKey("amr"));
        Assert.Null(roundTripToken.Payload.Json.GetArrayOfStringsOrNull("amr"));
    }

    /// <summary>
    /// Verifies that optional array claims with values round-trip correctly.
    /// Tests amr (Authentication Methods References) claim with multiple factors.
    /// Per OIDC Core Section 2, amr identifies authentication methods used (pwd, mfa, etc.).
    /// </summary>
    [Fact]
    public async Task ArrayClaimOrNull_WithValues_RoundTrip_PreservesValues()
    {
        var token = CreateToken();
        var values = new[] { "pwd", "mfa" };
        token.Payload.Json.SetArrayOrStringOrNull("amr", values);

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualValues = roundTripToken.Payload.Json.GetArrayOfStringsOrNull("amr")?.ToArray();
        Assert.NotNull(actualValues);
        Assert.Equal(values, actualValues);
    }

    /// <summary>
    /// Verifies that space-separated string claims with single value round-trip correctly.
    /// Tests OAuth 2.0 "scope" claim format per RFC 6749 Section 3.3.
    /// Single scope is stored as simple string (e.g., "openid").
    /// </summary>
    [Fact]
    public async Task SpaceSeparatedStringClaim_SingleValue_RoundTrip_PreservesValue()
    {
        var token = CreateToken();
        var scopes = new[] { "openid" };
        token.Payload.Json.SetSpaceSeparatedStrings("scope", scopes);

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualScopes = roundTripToken.Payload.Json.GetSpaceSeparatedStrings("scope").ToArray();
        Assert.Equal(scopes, actualScopes);
    }

    /// <summary>
    /// Verifies that space-separated string claims with multiple values round-trip correctly.
    /// Tests OAuth 2.0 "scope" claim with multiple scopes (e.g., "openid profile email").
    /// Per RFC 6749, scopes are space-delimited, case-sensitive strings.
    /// </summary>
    [Fact]
    public async Task SpaceSeparatedStringClaim_MultipleValues_RoundTrip_PreservesValues()
    {
        var token = CreateToken();
        var scopes = new[] { "openid", "profile", "email", "phone" };
        token.Payload.Json.SetSpaceSeparatedStrings("scope", scopes);

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualScopes = roundTripToken.Payload.Json.GetSpaceSeparatedStrings("scope").ToArray();
        Assert.Equal(scopes, actualScopes);
    }

    /// <summary>
    /// Verifies that space-separated string claims with empty values are removed from payload.
    /// Tests edge case of scope claim with no values (should be omitted or treated as no scope).
    /// </summary>
    [Fact]
    public async Task SpaceSeparatedStringClaim_EmptyArray_RoundTrip_IsRemovedFromPayload()
    {
        var token = CreateToken();
        token.Payload.Json.SetSpaceSeparatedStrings("scope", []);

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualScopes = roundTripToken.Payload.Json.GetSpaceSeparatedStrings("scope").ToArray();
        Assert.Empty(actualScopes);
    }

    /// <summary>
    /// Verifies that JWT structured claims (JSON objects) round-trip correctly.
    /// Tests OIDC address claim with nested fields (street, city, state, zip).
    /// Per OIDC Core Section 5.1.1, address is a JSON object with standard fields.
    /// </summary>
    [Fact]
    public async Task StructuredClaim_SimpleObject_RoundTrip_PreservesStructure()
    {
        var token = CreateToken();
        var address = new JsonObject
        {
            { "street", "123 Main St" },
            { "city", "Springfield" },
            { "state", "IL" },
            { "zip", "62701" }
        };
        token.Payload["address"] = address;

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualAddress = roundTripToken.Payload.Json["address"] as JsonObject;
        Assert.NotNull(actualAddress);
        Assert.Equal("123 Main St", actualAddress["street"]?.GetValue<string>());
        Assert.Equal("Springfield", actualAddress["city"]?.GetValue<string>());
        Assert.Equal("IL", actualAddress["state"]?.GetValue<string>());
        Assert.Equal("62701", actualAddress["zip"]?.GetValue<string>());
    }

    /// <summary>
    /// Verifies that deeply nested JSON objects (3+ levels) round-trip correctly.
    /// Tests complex structured claims with multiple nesting levels.
    /// Important for custom claims containing hierarchical data.
    /// </summary>
    [Fact]
    public async Task StructuredClaim_NestedObject_RoundTrip_PreservesStructure()
    {
        var token = CreateToken();
        var userProfile = new JsonObject
        {
            { "name", "John Doe" },
            { "age", 30 },
            { "email", "john@example.com" },
            {
                "address", new JsonObject
                {
                    { "street", "456 Oak Ave" },
                    { "city", "New York" },
                    {
                        "coordinates", new JsonObject
                        {
                            { "lat", 40.7128 },
                            { "lng", -74.0060 }
                        }
                    }
                }
            }
        };
        token.Payload["profile"] = userProfile;

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualProfile = roundTripToken.Payload.Json["profile"] as JsonObject;
        Assert.NotNull(actualProfile);
        Assert.Equal("John Doe", actualProfile["name"]?.GetValue<string>());
        Assert.Equal(30, actualProfile["age"]?.GetValue<int>());

        var actualAddress = actualProfile["address"] as JsonObject;
        Assert.NotNull(actualAddress);
        Assert.Equal("456 Oak Ave", actualAddress["street"]?.GetValue<string>());

        var actualCoords = actualAddress["coordinates"] as JsonObject;
        Assert.NotNull(actualCoords);
        var lat = actualCoords["lat"]?.GetValue<double>();
        var lng = actualCoords["lng"]?.GetValue<double>();
        Assert.NotNull(lat);
        Assert.NotNull(lng);
        Assert.Equal(40.7128, lat.Value, precision: 4);
        Assert.Equal(-74.0060, lng.Value, precision: 4);
    }

    /// <summary>
    /// Verifies that JSON objects containing arrays round-trip correctly.
    /// Tests complex structures combining objects and arrays (e.g., organization with employees).
    /// Supports custom claims with rich data structures.
    /// </summary>
    [Fact]
    public async Task StructuredClaim_ObjectWithArray_RoundTrip_PreservesStructure()
    {
        var token = CreateToken();
        var organization = new JsonObject
        {
            { "name", "Acme Corp" },
            { "departments", new JsonArray("Engineering", "Sales", "Marketing") },
            {
                "employees", new JsonArray
                {
                    new JsonObject { { "id", 1 }, { "name", "Alice" } },
                    new JsonObject { { "id", 2 }, { "name", "Bob" } }
                }
            }
        };
        token.Payload["organization"] = organization;

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualOrg = roundTripToken.Payload.Json["organization"] as JsonObject;
        Assert.NotNull(actualOrg);
        Assert.Equal("Acme Corp", actualOrg["name"]?.GetValue<string>());

        var actualDepts = actualOrg["departments"] as JsonArray;
        Assert.NotNull(actualDepts);
        Assert.Equal(3, actualDepts.Count);
        Assert.Equal("Engineering", actualDepts[0]?.GetValue<string>());

        var actualEmployees = actualOrg["employees"] as JsonArray;
        Assert.NotNull(actualEmployees);
        Assert.Equal(2, actualEmployees.Count);

        var firstEmployee = actualEmployees[0] as JsonObject;
        Assert.NotNull(firstEmployee);
        Assert.Equal(1, firstEmployee["id"]?.GetValue<int>());
        Assert.Equal("Alice", firstEmployee["name"]?.GetValue<string>());
    }

    /// <summary>
    /// Verifies that empty JSON objects {} are preserved in JWT payload.
    /// Unlike empty arrays, empty objects may have semantic meaning and are preserved.
    /// Tests edge case of structured claims with no content.
    /// </summary>
    [Fact]
    public async Task StructuredClaim_EmptyObject_RoundTrip_PreservesEmptyObject()
    {
        var token = CreateToken();
        token.Payload["empty_object"] = new JsonObject();

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualObject = roundTripToken.Payload.Json["empty_object"] as JsonObject;
        Assert.NotNull(actualObject);
        Assert.Empty(actualObject);
    }

    /// <summary>
    /// Verifies that JSON arrays containing mixed primitive types round-trip correctly.
    /// Tests arrays with strings, numbers, booleans, and doubles.
    /// Per JSON spec, arrays can contain heterogeneous types.
    /// </summary>
    [Fact]
    public async Task ArrayClaim_MixedSimpleTypes_RoundTrip_PreservesStructure()
    {
        var token = CreateToken();
        var items = new JsonArray
        {
            "simple_string",
            42,
            true,
            3.14
        };
        token.Payload["mixed_array"] = items;

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualItems = roundTripToken.Payload.Json["mixed_array"] as JsonArray;
        Assert.NotNull(actualItems);
        Assert.Equal(4, actualItems.Count);
        Assert.Equal("simple_string", actualItems[0]?.GetValue<string>());
        Assert.Equal(42, actualItems[1]?.GetValue<int>());
        Assert.True(actualItems[2]?.GetValue<bool>());
        var doubleValue = actualItems[3]?.GetValue<double>();
        Assert.NotNull(doubleValue);
        Assert.Equal(3.14, doubleValue.Value, precision: 2);
    }

    /// <summary>
    /// Verifies that DateTime claims stored as Unix timestamps (NumericDate) round-trip correctly.
    /// Per RFC 7519 Section 2, NumericDate is seconds since 1970-01-01T00:00:00Z.
    /// Critical for iat, exp, nbf, auth_time claims.
    /// </summary>
    [Fact]
    public async Task DateTimeClaim_UnixTimestamp_RoundTrip_PreservesValue()
    {
        var token = CreateToken();
        var testTime = new DateTimeOffset(2024, 11, 6, 12, 30, 45, TimeSpan.Zero);
        token.Payload.Json.SetUnixTimeSeconds("custom_time", testTime);

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualTime = roundTripToken.Payload.Json.GetUnixTimeSeconds("custom_time");
        Assert.NotNull(actualTime);
        Assert.Equal(testTime.ToUnixTimeSeconds(), actualTime.Value.ToUnixTimeSeconds());
    }

    /// <summary>
    /// Verifies that null DateTime claims are removed from JWT payload.
    /// Tests optional timestamp claims (e.g., auth_time may be omitted).
    /// </summary>
    [Fact]
    public async Task DateTimeClaim_NullValue_RoundTrip_IsRemovedFromPayload()
    {
        var token = CreateToken();
        token.Payload.Json.SetUnixTimeSeconds("custom_time", null);

        var roundTripToken = await SignEncryptAndValidate(token);

        Assert.False(roundTripToken.Payload.Json.ContainsKey("custom_time"));
        Assert.Null(roundTripToken.Payload.Json.GetUnixTimeSeconds("custom_time"));
    }

    /// <summary>
    /// Verifies that all standard JWT/OIDC claims round-trip correctly using built-in properties.
    /// Tests: jti, iss, sub, aud, iat, nbf, exp, client_id, sid, scope, idp, auth_time, nonce, amr, acr, email, email_verified.
    /// Per RFC 7519 and OIDC Core, these are the standard registered claims.
    /// Critical integration test for complete JWT payload handling.
    /// </summary>
    [Fact]
    public async Task StandardClaims_BuiltInProperties_RoundTrip_PreservesValues()
    {
        var token = CreateToken();
        var issuedAt = DateTimeOffset.UtcNow;

        token.Payload.JwtId = Guid.NewGuid().ToString("N");
        token.Payload.Issuer = "https://issuer.example.com";
        token.Payload.Subject = "user123";
        token.Payload.Audiences = ["audience1"];
        token.Payload.IssuedAt = issuedAt;
        token.Payload.NotBefore = issuedAt;
        token.Payload.ExpiresAt = issuedAt.AddHours(1);
        token.Payload.ClientId = "client_abc";
        token.Payload.SessionId = "session_xyz";
        token.Payload.Scope = ["openid", "profile"];
        token.Payload.IdentityProvider = "https://idp.example.com";
        token.Payload.AuthenticationTime = issuedAt.AddMinutes(-5);
        token.Payload.Nonce = "nonce_value";
        token.Payload.AuthenticationMethodReferences = ["pwd", "mfa"];
        token.Payload.AuthContextClassRef = "urn:mace:incommon:iap:silver";
        token.Payload.Email = "user@example.com";
        token.Payload.EmailVerified = true;

        var roundTripToken = await SignEncryptAndValidate(token);

        Assert.Equal(token.Payload.JwtId, roundTripToken.Payload.JwtId);
        Assert.Equal(token.Payload.Issuer, roundTripToken.Payload.Issuer);
        Assert.Equal(token.Payload.Subject, roundTripToken.Payload.Subject);
        Assert.Equal(token.Payload.Audiences, roundTripToken.Payload.Audiences);
        Assert.Equal(token.Payload.IssuedAt?.ToUnixTimeSeconds(), roundTripToken.Payload.IssuedAt?.ToUnixTimeSeconds());
        Assert.Equal(token.Payload.NotBefore?.ToUnixTimeSeconds(), roundTripToken.Payload.NotBefore?.ToUnixTimeSeconds());
        Assert.Equal(token.Payload.ExpiresAt?.ToUnixTimeSeconds(), roundTripToken.Payload.ExpiresAt?.ToUnixTimeSeconds());
        Assert.Equal(token.Payload.ClientId, roundTripToken.Payload.ClientId);
        Assert.Equal(token.Payload.SessionId, roundTripToken.Payload.SessionId);
        Assert.Equal(token.Payload.Scope, roundTripToken.Payload.Scope);
        Assert.Equal(token.Payload.IdentityProvider, roundTripToken.Payload.IdentityProvider);
        Assert.Equal(token.Payload.AuthenticationTime?.ToUnixTimeSeconds(), roundTripToken.Payload.AuthenticationTime?.ToUnixTimeSeconds());
        Assert.Equal(token.Payload.Nonce, roundTripToken.Payload.Nonce);
        Assert.Equal(token.Payload.AuthenticationMethodReferences, roundTripToken.Payload.AuthenticationMethodReferences);
        Assert.Equal(token.Payload.AuthContextClassRef, roundTripToken.Payload.AuthContextClassRef);
        Assert.Equal(token.Payload.Email, roundTripToken.Payload.Email);
        Assert.Equal(token.Payload.EmailVerified, roundTripToken.Payload.EmailVerified);
    }

    /// <summary>
    /// Verifies that very long string claims (10,000 characters) round-trip correctly.
    /// Tests JWT handling of large payload sizes.
    /// Note: Very large JWTs may exceed HTTP header limits (~8KB) and should be avoided.
    /// </summary>
    [Fact]
    public async Task VeryLongStringClaim_RoundTrip_PreservesValue()
    {
        var token = CreateToken();
        var longString = new string('x', 10_000);
        token.Payload["long_claim"] = longString;

        var roundTripToken = await SignEncryptAndValidate(token);

        var actualValue = roundTripToken.Payload.Json.GetProperty<string>("long_claim");
        Assert.Equal(longString, actualValue);
        Assert.Equal(10_000, actualValue?.Length);
    }

    /// <summary>
    /// Verifies that JWTs with all claim types simultaneously round-trip correctly.
    /// Comprehensive integration test combining:
    /// - Standard claims (jti, iss, sub, aud, iat, nbf, exp)
    /// - Simple types (string, int, bool, double)
    /// - Arrays (roles, scopes, colors)
    /// - Structured objects (address with coordinates)
    /// - Mixed arrays
    /// Tests realistic production JWT with diverse claim types.
    /// </summary>
    [Fact]
    public async Task ComplexScenario_AllClaimTypes_RoundTrip_PreservesAllValues()
    {
        var token = CreateToken();
        var issuedAt = DateTimeOffset.UtcNow;

        token.Payload.JwtId = Guid.NewGuid().ToString("N");
        token.Payload.Issuer = "https://issuer.example.com";
        token.Payload.Subject = "user123";
        token.Payload.Audiences = ["api1"];
        token.Payload.IssuedAt = issuedAt;
        token.Payload.NotBefore = issuedAt;
        token.Payload.ExpiresAt = issuedAt.AddHours(1);

        token.Payload["string_claim"] = "simple value";
        token.Payload["int_claim"] = 42;
        token.Payload["bool_claim"] = true;
        token.Payload["double_claim"] = 3.14159;

        token.Payload.Json.SetArrayOrString("roles", ["admin", "user", "moderator"]);
        token.Payload.Json.SetSpaceSeparatedStrings("scope", ["openid", "profile", "email"]);

        token.Payload["address"] = new JsonObject
        {
            { "street", "123 Main St" },
            { "city", "Springfield" },
            { "coordinates", new JsonObject { { "lat", 40.7128 }, { "lng", -74.0060 } } }
        };

        token.Payload["colors"] = new JsonArray("red", "green", "blue");

        token.Payload["mixed_array"] = new JsonArray
        {
            "string",
            123,
            true,
            new JsonObject { { "nested", "value" } }
        };

        var roundTripToken = await SignEncryptAndValidate(token);

        Assert.Equal(token.Payload.Subject, roundTripToken.Payload.Subject);
        Assert.Equal("simple value", roundTripToken.Payload.Json.GetProperty<string>("string_claim"));
        Assert.Equal(42, roundTripToken.Payload.Json.GetProperty<int>("int_claim"));
        Assert.True(roundTripToken.Payload.Json.GetProperty<bool>("bool_claim"));

        var roles = roundTripToken.Payload.Json.GetArrayOfStrings("roles").ToArray();
        Assert.Equal(new[] { "admin", "user", "moderator" }, roles);

        var scopes = roundTripToken.Payload.Json.GetSpaceSeparatedStrings("scope").ToArray();
        Assert.Equal(new[] { "openid", "profile", "email" }, scopes);

        var address = roundTripToken.Payload.Json["address"] as JsonObject;
        Assert.NotNull(address);
        Assert.Equal("123 Main St", address["street"]?.GetValue<string>());

        var colors = roundTripToken.Payload.Json.GetArrayOfStrings("colors").ToArray();
        Assert.Equal(new[] { "red", "green", "blue" }, colors);
    }

    /// <summary>
    /// Verifies that GetArrayOfStrings correctly filters out null elements from JsonArray.
    /// Tests the OfType&lt;JsonNode&gt;() null filtering behavior when parsing arrays that may contain nulls.
    /// This is important for defensive parsing of JWT claims from untrusted sources.
    /// </summary>
    [Fact]
    public void GetArrayOfStrings_WithNullElements_FiltersOutNulls()
    {
        var token = CreateToken();

        // Create a JsonArray with null elements
        token.Payload.Json["colors"] = new JsonArray
        {
            "red",
            null,
            "green",
            null,
            "blue"
        };

        var result = token.Payload.Json.GetArrayOfStrings("colors").ToArray();

        Assert.Equal(3, result.Length);
        Assert.Equal(["red", "green", "blue"], result);
    }

    private static JsonWebToken CreateToken()
    {
        var issuedAt = DateTimeOffset.UtcNow;
        return new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                JwtId = Guid.NewGuid().ToString("N"),
                IssuedAt = issuedAt,
                NotBefore = issuedAt,
                ExpiresAt = issuedAt + TimeSpan.FromHours(1),
            },
        };
    }

    private static async Task<JsonWebToken> SignEncryptAndValidate(JsonWebToken token)
    {
        var creator = new JsonWebTokenCreator();
        var jwt = await creator.IssueAsync(token, SigningKey, EncryptingKey);

        var validator = new JsonWebTokenValidator();
        var parameters = new ValidationParameters
        {
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveTokenDecryptionKeys = _ => new[] { EncryptingKey }.ToAsyncEnumerable(),
            ResolveIssuerSigningKeys = _ => new[] { SigningKey }.ToAsyncEnumerable(),
            Options = ValidationOptions.Default & ~ValidationOptions.ValidateLifetime
        };

        var validatorResult = await validator.ValidateAsync(jwt, parameters);
        Assert.True(validatorResult.TryGetSuccess(out var result));
        return result;
    }
}
