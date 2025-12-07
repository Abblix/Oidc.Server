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

using System.Security.Cryptography.X509Certificates;
using System.Text;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Utils;
using JsonWebKey = Abblix.Jwt.JsonWebKey;

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// Handles the loading and validation of application licenses provided as JSON Web Tokens (JWT).
/// </summary>
/// <remarks>
/// This class is responsible for validating the integrity and authenticity of the license JWT against predefined
/// criteria, including issuer validation and signature verification. Upon successful validation, it extracts and
/// applies license details to configure application features and limits accordingly.
/// </remarks>
public class LicenseLoader
{
    private const string ValidIssuer = "https://abblix.com";
    private const string ValidLicenseType = "urn:abblix.com:oidc.server:license";

    /// <summary>
    /// Asynchronously loads and validates the license JWT, applying the license details upon successful validation.
    /// </summary>
    /// <param name="licenseJwt">The license JWT string to be loaded and validated.</param>
    /// <exception cref="InvalidOperationException">
    /// Thrown if the JWT type is not valid or if the license cannot be validated.</exception>
    /// <exception cref="UnexpectedTypeException">Thrown if an unexpected validation result type is encountered.
    /// </exception>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public static async Task LoadAsync(string licenseJwt)
    {
        var validationResult = await new JsonWebTokenValidator().ValidateAsync(
            licenseJwt,
            new ValidationParameters
            {
                Options = ValidationOptions.ValidateIssuer |
                          ValidationOptions.RequireSignedTokens |
                          ValidationOptions.ValidateIssuerSigningKey,

                ValidateIssuer = ValidateIssuer,
                ResolveIssuerSigningKeys = ResolveIssuerSigningKeys,
            });

        if (validationResult.TryGetFailure(out var error))
            throw new InvalidOperationException(
                $"The license can't be validated: [{error.Error}] {error.ErrorDescription}");

        var token = validationResult.GetSuccess();

        if (token.Header.Type != ValidLicenseType)
        {
            throw new InvalidOperationException("The JWT type is not valid");
        }

        var license = new License
        {
            NotBefore = token.Payload.NotBefore,
            ExpiresAt = token.Payload.ExpiresAt,
            GracePeriod = token.Payload.Json.GetUnixTimeSeconds("grace_period"),
            ClientLimit = token.Payload["client_limit"]?.GetValue<int>(),
            IssuerLimit = token.Payload["issuer_limit"]?.GetValue<int>(),
            ValidIssuers = token.Payload.Json.GetArrayOfStrings("valid_issuers").ToHashSet(StringComparer.Ordinal),
        };
        LicenseChecker.AddLicense(license);
    }

    /// <summary>
    /// Validates the issuer of the license JWT against a predefined valid issuer.
    /// </summary>
    /// <param name="issuer">The issuer URL to validate.</param>
    /// <returns>A <see cref="Task"/> indicating whether the issuer is valid.</returns>
    private static Task<bool> ValidateIssuer(string issuer)
        => Task.FromResult(issuer == ValidIssuer);

    /// <summary>
    /// Resolves the signing keys for the issuer of the license JWT, required for signature validation.
    /// </summary>
    /// <param name="issuer">The issuer URL whose signing keys are to be resolved.</param>
    /// <returns>An asynchronous stream of <see cref="JsonWebKey"/> objects representing the issuer's signing keys.
    /// </returns>
    private static async IAsyncEnumerable<JsonWebKey> ResolveIssuerSigningKeys(string issuer)
    {
        if (issuer != ValidIssuer)
            yield break;

        var pem = await GetSigningKeyPem();
        var certificate = X509Certificate2.CreateFromPem(pem);
        var jwk = certificate.ToJsonWebKey();
        yield return jwk;
    }

    /// <summary>
    /// Retrieves the PEM-encoded signing key for the license JWT from embedded resources.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing the PEM-encoded signing key.</returns>
    private static async Task<string> GetSigningKeyPem()
    {
        var type = typeof(LicenseLoader);
        var name = $"{type.Namespace}.Resources.Abblix Licensing.pem";

        await using var stream = type.Assembly.GetManifestResourceStream(name).NotNull(name);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return await reader.ReadToEndAsync();
    }
}
