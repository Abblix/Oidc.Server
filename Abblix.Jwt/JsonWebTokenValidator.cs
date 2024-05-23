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
    public IEnumerable<string> SigningAlgValuesSupported => JsonWebTokenAlgorithms.SigningAlgValuesSupported;

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
            }
        };

        foreach (var claim in jwToken.Claims.ExceptBy(JwtSecurityTokenHandlerConstants.ClaimTypesToExclude, claim => claim.Type))
        {
            result.Payload[claim.Type] = ToJsonNode(claim.ValueType, claim.Value);
        }

        return new ValidJsonWebToken(result);
    }


    /// <summary>
    /// Creates a <see cref="JsonNode"/> representation of a claim value based on its type.
    /// </summary>
    /// <param name="valueType">The type of the claim value.</param>
    /// <param name="value">The string representation of the claim value.</param>
    /// <returns>A <see cref="JsonNode"/> representing the claim value.</returns>
    private static JsonNode? ToJsonNode(string valueType, string value)
        => valueType switch
        {
            JsonClaimValueTypes.Json => JsonNode.Parse(value).NotNull(nameof(value)),

            ClaimValueTypes.Boolean => JsonValue.Create(bool.Parse(value)),
            ClaimValueTypes.Integer => JsonValue.Create(long.Parse(value)),
            ClaimValueTypes.Integer32 => JsonValue.Create(int.Parse(value)),
            ClaimValueTypes.Integer64 => JsonValue.Create(long.Parse(value)),

            _ => value,
        };
}
