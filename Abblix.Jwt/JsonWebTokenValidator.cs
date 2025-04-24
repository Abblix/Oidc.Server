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

using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json.Nodes;
using Abblix.Utils;
using Microsoft.IdentityModel.Tokens;

namespace Abblix.Jwt;

/// <summary>
/// Represents a validator for JSON Web Tokens (JWTs) which validates a JWT against specified validation parameters.
/// </summary>
public class JsonWebTokenValidator : IJsonWebTokenValidator
{
    /// <summary>
    /// Provides a collection of signing algorithms supported by the validator. This includes all algorithms recognized
    /// by the JwtSecurityTokenHandler for inbound tokens, as well as an option to accept tokens without a signature.
    /// This allows for flexibility in validating JWTs with various security requirements.
    /// </summary>
    public IEnumerable<string> SigningAlgorithmsSupported => JsonWebTokenAlgorithms.SigningAlgValuesSupported;

    /// <summary>
    /// Asynchronously validates a JWT string against specified validation parameters.
    /// </summary>
    /// <param name="jwt">The JWT string to validate.</param>
    /// <param name="parameters">The parameters defining the validation rules and requirements.</param>
    /// <returns>A task representing the validation operation, with a result of JwtValidationResult indicating the validation outcome.</returns>
    public Task<JwtValidationResult> ValidateAsync(string jwt, ValidationParameters parameters)
        => Task.FromResult(Validate(jwt, parameters));

    /// <summary>
    /// Performs the actual validation of a JWT string based on the specified validation parameters.
    /// </summary>
    /// <param name="jwt">The JWT string to validate.</param>
    /// <param name="parameters">The validation parameters.</param>
    /// <returns>The result of the JWT validation process, either indicating success or detailing any validation errors.</returns>
    private static JwtValidationResult Validate(string jwt, ValidationParameters parameters)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            NameClaimType = JwtClaimTypes.Subject,

            ValidateIssuer = parameters.Options.HasFlag(ValidationOptions.ValidateIssuer),
            ValidateAudience = parameters.Options.HasFlag(ValidationOptions.ValidateAudience),
            RequireSignedTokens = parameters.Options.HasFlag(ValidationOptions.RequireSignedTokens),
            ValidateIssuerSigningKey = parameters.Options.HasFlag(ValidationOptions.ValidateIssuerSigningKey),
            ValidateLifetime = parameters.Options.HasFlag(ValidationOptions.ValidateLifetime),
        };

        if (tokenValidationParameters.ValidateIssuer)
        {
            var validateIssuer = parameters.ValidateIssuer
                .NotNull(nameof(parameters.ValidateIssuer));

            tokenValidationParameters.IssuerValidator = (issuer, _, _) =>
                validateIssuer(issuer).Result ? issuer : null;
        }

        if (tokenValidationParameters.ValidateAudience)
        {
            var validateAudience = parameters.ValidateAudience
                .NotNull(nameof(parameters.ValidateAudience));

            tokenValidationParameters.AudienceValidator = (audiences, _, _) =>
                validateAudience(audiences).Result;
        }

        if (tokenValidationParameters.ValidateIssuerSigningKey)
        {
            var resolveIssuerSigningKeys = parameters.ResolveIssuerSigningKeys
                .NotNull(nameof(parameters.ResolveIssuerSigningKeys));

            tokenValidationParameters.IssuerSigningKeyResolver = (_, securityToken, keyId, _) =>
            {
                var signingKeys = resolveIssuerSigningKeys(securityToken.Issuer);

                if (keyId.HasValue())
                    signingKeys = signingKeys.Where(key => key.KeyId == keyId);

                return signingKeys.Select(key => key.ToSecurityKey()).ToListAsync().Result;
            };
        }

        var resolveTokenDecryptionKeys = parameters.ResolveTokenDecryptionKeys;
        if (resolveTokenDecryptionKeys != null)
            tokenValidationParameters.TokenDecryptionKeyResolver = (_, securityToken, keyId, _) =>
            {
                var decryptionKeys = resolveTokenDecryptionKeys(securityToken.Issuer);

                if (keyId.HasValue())
                    decryptionKeys = decryptionKeys.Where(key => key.KeyId == keyId);

                return decryptionKeys.Select(key => key.ToSecurityKey()).ToListAsync().Result;
            };

        var handler = new JwtSecurityTokenHandler();
        SecurityToken token;
        try
        {
            handler.ValidateToken(jwt, tokenValidationParameters, out token);
        }
        catch (Exception ex)
        {
            return new JwtValidationError(JwtError.InvalidToken, ex.Message);
        }

        var jwToken = (JwtSecurityToken)token;

        var result = new JsonWebToken
        {
            Header =
            {
                Type = jwToken.Header.Typ,
                Algorithm = jwToken.Header.Alg,
            },
            Payload =
            {
                JwtId = jwToken.Id,
                IssuedAt = jwToken.IssuedAt,
                NotBefore = jwToken.ValidFrom,
                ExpiresAt = jwToken.ValidTo,
                Issuer = jwToken.Issuer,
                Audiences = jwToken.Audiences,
            },
        };

        MergeClaims(jwToken.Claims, result.Payload.Json, JwtSecurityTokenHandlerConstants.ClaimTypesToExclude);

        return new ValidJsonWebToken(result);
    }

    /// <summary>
    /// Merges a set of claims into a <see cref="JsonObject"/>, excluding specified claim types.
    /// </summary>
    /// <remarks>
    /// Each claim is converted to a <see cref="JsonNode"/> using <c>ToJsonNode</c>.
    /// - Claims with a single value are stored as a <see cref="JsonValue"/>.
    /// - Claims with multiple values are stored in a <see cref="JsonArray"/>.
    ///
    /// Excluded claim types will be skipped entirely.
    /// Ensure that returned <see cref="JsonNode"/> instances are not reused elsewhere in the JSON tree,
    /// as <c>System.Text.Json.Nodes</c> does not allow a node to have more than one parent.
    /// </remarks>
    /// <param name="claims">The collection of claims to merge.</param>
    /// <param name="json">The target <see cref="JsonObject"/> to populate with merged claims.</param>
    /// <param name="claimTypesToExclude">An array of claim type identifiers that should be excluded from the merge.
    /// </param>
    /// <exception cref="InvalidOperationException">Thrown if a grouped claim contains no values,
    /// which should not occur under normal circumstances.</exception>
    private static void MergeClaims(IEnumerable<Claim> claims, JsonObject json, string[] claimTypesToExclude)
    {
        var claimGroups = claims
            .Where(claim => !claimTypesToExclude.Contains(claim.Type))
            .GroupBy(claim => claim.Type, claim => ToJsonNode(claim.ValueType, claim.Value));

        foreach (var claimGroup in claimGroups)
        {
            using var enumerator = claimGroup.GetEnumerator();
            if (!enumerator.MoveNext())
                throw new InvalidOperationException("Claim group contains no claims.");

            var claimValue = enumerator.Current;
            if (enumerator.MoveNext())
            {
                // convert values to array
                var jsonArray = new JsonArray { claimValue };
                do
                {
                    jsonArray.Add(enumerator.Current);
                } while (enumerator.MoveNext());

                claimValue = jsonArray;
            }
            json[claimGroup.Key] = claimValue;
        }
    }

    /// <summary>
    /// Creates a <see cref="JsonNode"/> representation of a claim value based on its type.
    /// </summary>
    /// <param name="valueType">The type of the claim value.</param>
    /// <param name="value">The string representation of the claim value.</param>
    /// <returns>A <see cref="JsonNode"/> representing the claim value.</returns>
    private static JsonNode? ToJsonNode(string valueType, string value) => valueType switch
    {
        JsonClaimValueTypes.Json => JsonNode.Parse(value).NotNull(nameof(value)),

        ClaimValueTypes.Boolean => JsonValue.Create(bool.Parse(value)),
        ClaimValueTypes.Integer or ClaimValueTypes.Integer64 => JsonValue.Create(long.Parse(value)),
        ClaimValueTypes.Integer32 => JsonValue.Create(int.Parse(value)),
        ClaimValueTypes.Date or ClaimValueTypes.DateTime => JsonValue.Create(DateTimeOffset.Parse(value)),
        ClaimValueTypes.Time => JsonValue.Create(TimeSpan.Parse(value)),

        ClaimValueTypes.Double => JsonValue.Create(double.Parse(value, CultureInfo.InvariantCulture)),
        ClaimValueTypes.HexBinary => JsonValue.Create(Convert.FromHexString(value)),
        ClaimValueTypes.Base64Binary or ClaimValueTypes.Base64Octet => JsonValue.Create(Convert.FromBase64String(value)),

        ClaimValueTypes.UInteger32 => JsonValue.Create(uint.Parse(value, CultureInfo.InvariantCulture)),
        ClaimValueTypes.UInteger64 => JsonValue.Create(ulong.Parse(value, CultureInfo.InvariantCulture)),

        // Default fallback: treat all other unknown types as string
        _ => JsonValue.Create(value),
    };
}
