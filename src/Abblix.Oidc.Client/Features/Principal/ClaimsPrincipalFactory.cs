// Abblix OIDC Client Library
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

using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.Features.Principal;

/// <summary>
/// Builds a principal from the claims of a validated ID Token, and nothing else.
/// </summary>
/// <param name="options">Which claim is the name, which carries roles, and how the identity is labelled.</param>
public sealed class ClaimsPrincipalFactory(IOptions<ClaimsPrincipalOptions> options) : IClaimsPrincipalFactory
{
    /// <inheritdoc />
    public ClaimsPrincipal Create(JsonWebToken identityToken)
    {
        var settings = options.Value;

        var identity = new ClaimsIdentity(
            ReadClaims(identityToken.Payload.Json),
            settings.AuthenticationType,
            settings.NameClaimType,
            settings.RoleClaimType);

        return new ClaimsPrincipal(identity);
    }

    /// <summary>
    /// Flattens the token's payload into claims.
    /// </summary>
    /// <remarks>
    /// Every claim the issuer stated is carried over, including ones this library does not model: a host
    /// that asked its provider for a claim should find it here, and dropping the unrecognised ones would
    /// make the principal depend on what this version happens to know about.
    /// </remarks>
    private static IEnumerable<Claim> ReadClaims(JsonObject payload)
    {
        foreach (var (name, value) in payload)
        {
            // A claim whose value is an array is several claims of the same name, which is how
            // ClaimsPrincipal represents multi-valued claims and what its role checks expect.
            if (value is JsonArray array)
            {
                // A JSON null element is a legal value from the issuer, not a broken token: it states
                // nothing, so it becomes no claim rather than an empty one. Dropped by OfType, which both
                // filters and narrows, so the value reaching ToClaim is known non-null rather than asserted.
                foreach (var element in array.OfType<JsonNode>())
                    yield return ToClaim(name, element);

                continue;
            }

            if (value is not null)
                yield return ToClaim(name, value);
        }
    }

    /// <summary>
    /// Represents one JSON value as a claim.
    /// </summary>
    /// <remarks>
    /// A scalar becomes its text; anything structured keeps its JSON, because flattening an object would
    /// lose the shape the issuer meant and a caller can parse what it was given. The value type is recorded
    /// either way, so a consumer can tell "the string 42" from "the number 42" without guessing.
    /// </remarks>
    private static Claim ToClaim(string name, JsonNode value)
        => value is JsonValue scalar && scalar.TryGetValue<string>(out var text)
            ? new Claim(name, text, ClaimValueTypes.String)
            : new Claim(name, value.ToJsonString(), JsonValueType(value));

    private static string JsonValueType(JsonNode value)
        => value.GetValueKind() switch
        {
            JsonValueKind.True or JsonValueKind.False => ClaimValueTypes.Boolean,
            JsonValueKind.Number => ClaimValueTypes.Double,
            _ => JsonValueTypeName,
        };

    /// <summary>
    /// The value type recorded for a claim whose value stayed JSON.
    /// </summary>
    /// <remarks>
    /// Spelled out here rather than taken from <c>JsonClaimValueTypes</c>, which lives in Microsoft's JWT
    /// packages: the string is the same one those use, and this client does not take a dependency to borrow
    /// a constant.
    /// </remarks>
    private const string JsonValueTypeName = "JSON";
}
