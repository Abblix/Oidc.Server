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
using Microsoft.IdentityModel.Tokens;

namespace Abblix.Jwt;

/// <summary>
/// Responsible for creating JSON Web Tokens (JWTs). This class provides functionality to issue JWTs based on given claims and keys.
/// </summary>
/// <remarks>
/// The class uses <see cref="SecurityTokenDescriptor"/> to define the token's properties and leverages <see cref="JwtSecurityTokenHandler"/>
/// for token creation. It supports setting standard claims such as issuer, audience, and times, as well as custom claims
/// contained within the provided <see cref="JsonWebToken"/> instance.
/// </remarks>
public sealed class JsonWebTokenCreator : IJsonWebTokenCreator
{
    /// <summary>
    /// Gets the collection of signing algorithms supported for JWT creation.
    /// This property reflects the JWT security token handler's default outbound algorithm mapping,
    /// indicating the algorithms available for signing the tokens.
    /// </summary>
    public IEnumerable<string> SigningAlgValuesSupported => JsonWebTokenAlgorithms.SigningAlgValuesSupported;

    /// <summary>
    /// Asynchronously issues a JWT based on the specified JsonWebToken, signing key, and optional encrypting key.
    /// </summary>
    /// <param name="jwt">The JsonWebToken object containing the payload of the JWT.</param>
    /// <param name="signingKey">The signing key as a JsonWebKey to sign the JWT.</param>
    /// <param name="encryptingKey">Optional encrypting key as a JsonWebKey to encrypt the JWT.</param>
    /// <returns>A Task that represents the asynchronous operation and yields the JWT as a string.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the specified date time values cause an overflow.</exception>
    /// <remarks>
    /// The method configures a <see cref="SecurityTokenDescriptor"/> based on the provided JWT, signing key, and encrypting key.
    /// It then creates the JWT using <see cref="JwtSecurityTokenHandler"/> and returns the serialized token string.
    /// Note: The audience is set to the first value if multiple audiences are provided, due to limitations of
    /// <see cref="JwtSecurityTokenHandler"/>.
    /// </remarks>
    public Task<string> IssueAsync(
        JsonWebToken jwt,
        JsonWebKey? signingKey,
        JsonWebKey? encryptingKey = null)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            TokenType = jwt.Header.Type,
            Issuer = jwt.Payload.Issuer,
            Audience = jwt.Payload.Audiences.SingleOrDefault(), //TODO replace JwtSecurityTokenHandler with own code to overcome this limitation

            IssuedAt = CheckDateOverflow(jwt.Payload.IssuedAt, nameof(jwt.Payload.IssuedAt)),
            NotBefore = CheckDateOverflow(jwt.Payload.NotBefore, nameof(jwt.Payload.NotBefore)),
            Expires = CheckDateOverflow(jwt.Payload.ExpiresAt, nameof(jwt.Payload.ExpiresAt)),

            Claims = Convert(jwt.Payload),
        };

        if (signingKey != null)
            descriptor.SigningCredentials = signingKey.ToSigningCredentials();

        if (encryptingKey != null)
            descriptor.EncryptingCredentials = encryptingKey.ToEncryptingCredentials();

        var token = new JwtSecurityTokenHandler().CreateJwtSecurityToken(descriptor);

        return Task.FromResult(token.RawData);
    }

    /// <summary>
    /// Checks if the specified DateTimeOffset is within the allowable range for JWT date/time claims.
    /// </summary>
    /// <param name="dateTime">The DateTimeOffset to check.</param>
    /// <param name="name">The name of the date/time claim for error reporting purposes.</param>
    /// <returns>A DateTime representation of the DateTimeOffset if it is within the allowable range.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the specified DateTimeOffset causes an overflow.</exception>
    /// <remarks>
    /// This method ensures that date/time claims do not exceed the maximum possible value that can be encoded in a JWT,
    /// preventing potential issues with token processing and validation.
    /// </remarks>
    private static DateTime? CheckDateOverflow(DateTimeOffset? dateTime, string name)
    {
        if (!dateTime.HasValue)
            return null;

        var maxPossibleDateTime = DateTimeOffset.UnixEpoch.AddSeconds(int.MaxValue);
        if (maxPossibleDateTime < dateTime)
            throw new ArgumentOutOfRangeException(name, dateTime, $"{name} value causes overflow: {dateTime}");

        return dateTime.Value.UtcDateTime;
    }

    /// <summary>
    /// Converts a collection of JwtClaims into a dictionary suitable for a JWT payload.
    /// </summary>
    /// <param name="payload">The JsonWebTokenPayload containing the claims to be converted.</param>
    /// <returns>A dictionary of claims where the key is the claim type and the value is the claim value.</returns>
    /// <remarks>
    /// This method facilitates the conversion of the JWT payload into a format compatible with <see cref="JwtSecurityTokenHandler"/>.
    /// It ensures that each claim is correctly represented, handling cases where claims have single or multiple values.
    /// </remarks>
    private static IDictionary<string, object> Convert(JsonWebTokenPayload payload)
    {
        var uniqueClaims = payload.Json
            .ExceptBy(
                JwtSecurityTokenHandlerConstants.ClaimTypesToExclude,
                claim => claim.Key)
            .GroupBy(
                claim => claim.Key,
                claim => claim.Value.ToJsonElement());

        var result = uniqueClaims.ToDictionary(
            claim => claim.Key,
            claim => claim.Count() == 1 ? (object)claim.Single() : claim.ToArray());

        return result;
    }
}
