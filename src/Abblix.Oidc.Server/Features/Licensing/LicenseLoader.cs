// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography.X509Certificates;
using System.Text;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
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
public static class LicenseLoader
{
    private const string ValidIssuer = "https://abblix.com";
    private const string ValidLicenseType = "urn:abblix.com:oidc.server:license";

    private static readonly IServiceProvider ServiceProvider = new ServiceCollection()
        .AddSingleton(TimeProvider.System)
        .AddLogging()
        .AddJsonWebTokens()
        .BuildServiceProvider();

    /// <summary>
    /// Asynchronously loads and validates the license JWT, applying the license details upon successful validation.
    /// </summary>
    /// <param name="licenseJwt">The license JWT string to be loaded and validated.</param>
    /// <exception cref="InvalidOperationException">
    /// Thrown if the JWT type is not valid or if the license cannot be validated.</exception>
    /// <exception cref="UnexpectedTypeException">Thrown if an unexpected validation result type is encountered.
    /// </exception>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    /// <remarks>
    /// Loading reports nothing, deliberately. A caller loads licenses one at a time, so every load but the
    /// last sees a partial set, and a license in its grace period would be announced before the renewal
    /// superseding it had arrived - once per superseded license, and only in the arrival order that puts
    /// the older one first. What the licenses mean is said on the next consult instead, and once at
    /// startup by the hosted service the registration extensions install, which is the moment the set has
    /// provably stopped growing.
    ///
    /// A host loading licenses through this method after startup therefore gets no record from the load
    /// itself. The consult that follows says everything except that a license still valid is expiring
    /// soon, which is the one status a valid cached license never reaches.
    /// </remarks>
    public static async Task LoadAsync(string licenseJwt)
    {
        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var validationResult = await validator.ValidateAsync(
            licenseJwt,
            new ValidationParameters
            {
                // RequireValidIssuer, not RequireIssuer: the delegate below is what decides whether this
                // licence was issued by us, and only ValidateIssuer runs it. The flag used to be RequireIssuer
                // alone and the delegate ran regardless, because the validator treated either flag as an
                // instruction to check. Once presence and validity became separate questions, this had to say
                // which one it meant.
                Options = ValidationOptions.RequireValidIssuer |
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

        LicenseChecker.AddLicense(ReadLicense(token.Payload));
    }

    /// <summary>
    /// Reads the licence terms out of a verified payload, refusing with the same message every other
    /// licence fault gets where a timestamp cannot be read.
    /// </summary>
    /// <remarks>
    /// Its own method, and internal, so that the read can be driven with a payload alone: the
    /// verification above needs a licence signed with the licensing key, which no test holds.
    /// </remarks>
    /// <param name="payload">The verified licence payload.</param>
    internal static License ReadLicense(JsonWebTokenPayload payload)
    {
        if (!payload.TryReadTimestamps(out var notBefore, out var expiresAt, out _, out var whyUnreadable)
            || !payload.TryReadTimestamp("grace_period", out var gracePeriod, out whyUnreadable))
        {
            throw new InvalidOperationException($"The license can't be validated: {whyUnreadable}");
        }

        return new License
        {
            NotBefore = notBefore,
            ExpiresAt = expiresAt,
            GracePeriod = gracePeriod,
            ClientLimit = payload["client_limit"]?.GetValue<int>(),
            IssuerLimit = payload["issuer_limit"]?.GetValue<int>(),
            ValidIssuers = payload.Json.GetArrayOfStrings("valid_issuers").ToHashSet(StringComparer.Ordinal),
        };
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
