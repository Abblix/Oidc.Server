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
                    signingKeys = signingKeys.WhereAsync(key => key.KeyId == keyId);

                return signingKeys.SelectAsync(key => key.ToSecurityKey()).ToListAsync().Result;
            };
        }

        var resolveTokenDecryptionKeys = parameters.ResolveTokenDecryptionKeys;
        if (resolveTokenDecryptionKeys != null)
            tokenValidationParameters.TokenDecryptionKeyResolver = (_, securityToken, keyId, _) =>
            {
                var decryptionKeys = resolveTokenDecryptionKeys(securityToken.Issuer);

                if (keyId.HasValue())
                    decryptionKeys = decryptionKeys.WhereAsync(key => key.KeyId == keyId);

                return decryptionKeys.SelectAsync(key => key.ToSecurityKey()).ToListAsync().Result;
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
