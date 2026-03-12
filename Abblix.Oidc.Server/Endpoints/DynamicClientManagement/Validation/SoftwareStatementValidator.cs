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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the software_statement parameter in a client registration request per RFC 7591 Section 2.3.
/// Software statements are signed JWTs issued by a third-party authority asserting metadata about client software.
/// </summary>
/// <param name="jwtValidator">Validates the software statement JWT signature and claims.</param>
/// <param name="options">OIDC options containing software statement configuration.</param>
/// <param name="secureFetcher">HTTP fetcher with SSRF protection for retrieving trusted issuer JWKS.</param>
/// <param name="logger">Logger for recording validation operations.</param>
public class SoftwareStatementValidator(
    IJsonWebTokenValidator jwtValidator,
    IOptionsMonitor<OidcOptions> options,
    ISecureHttpFetcher secureFetcher,
    ILogger<SoftwareStatementValidator> logger) : IClientRegistrationContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(ClientRegistrationValidationContext context)
    {
        var softwareStatementOptions = options.CurrentValue.SoftwareStatement;
        var softwareStatement = context.Request.SoftwareStatement;

        if (string.IsNullOrEmpty(softwareStatement))
        {
            if (softwareStatementOptions.RequireSoftwareStatement)
                return ErrorFactory.InvalidSoftwareStatement(
                    "A software_statement is required for client registration");

            return null;
        }

        if (softwareStatementOptions.TrustedIssuers.Length == 0)
        {
            return ErrorFactory.InvalidSoftwareStatement(
                "No trusted issuers configured for software statement validation");
        }

        var validationParameters = new ValidationParameters
        {
            // Skip audience — software statements describe the software, not target a specific server
            Options = ValidationOptions.Default &
                      ~ValidationOptions.RequireAudience &
                      ~ValidationOptions.ValidateAudience,

            ValidateIssuer = issuer => ValidateIssuer(softwareStatementOptions, issuer),
            ResolveIssuerSigningKeys = issuer => ResolveSigningKeysAsync(softwareStatementOptions, issuer),
        };

        var result = await jwtValidator.ValidateAsync(softwareStatement, validationParameters);

        if (result.TryGetFailure(out var error))
        {
            logger.LogWarning("Software statement validation failed: {Error}", error.ErrorDescription);
            return ErrorFactory.InvalidSoftwareStatement(
                $"The software_statement is invalid: {error.ErrorDescription}");
        }

        return ValidateSoftwareId(softwareStatementOptions, result.GetSuccess());
    }

    /// <summary>
    /// Checks whether the software statement issuer is in the configured trusted issuers list.
    /// </summary>
    private Task<bool> ValidateIssuer(SoftwareStatementOptions statementOptions, string issuer)
    {
        var trusted = FindTrustedIssuer(statementOptions, issuer) != null;
        if (!trusted)
            logger.LogDebug("Software statement issuer {Issuer} is not trusted", issuer);
        return Task.FromResult(trusted);
    }

    /// <summary>
    /// Checks the software_id claim from the validated software statement against
    /// the configured list of approved software identifiers.
    /// </summary>
    private static OidcError? ValidateSoftwareId(
        SoftwareStatementOptions statementOptions,
        JsonWebToken token)
    {
        if (statementOptions.ApprovedSoftwareIds is not { Count: > 0 })
            return null;

        var softwareId = token.Payload["software_id"]?.GetValue<string>();
        if (string.IsNullOrEmpty(softwareId) || !statementOptions.ApprovedSoftwareIds.Contains(softwareId))
        {
            return ErrorFactory.UnapprovedSoftwareStatement(
                $"The software_id '{softwareId}' is not approved for registration");
        }

        return null;
    }

    /// <summary>
    /// Finds a trusted issuer by exact match of the issuer identifier.
    /// </summary>
    private static TrustedIssuer? FindTrustedIssuer(SoftwareStatementOptions statementOptions, string issuer)
    {
        return statementOptions.TrustedIssuers.FirstOrDefault(
            ti => string.Equals(ti.Issuer, issuer, StringComparison.Ordinal));
    }

    /// <summary>
    /// Resolves signing keys for a trusted issuer by fetching its JWKS endpoint,
    /// filtering to keys suitable for signature verification.
    /// </summary>
    private async IAsyncEnumerable<JsonWebKey> ResolveSigningKeysAsync(
        SoftwareStatementOptions statementOptions,
        string issuer)
    {
        var trustedIssuer = FindTrustedIssuer(statementOptions, issuer);
        if (trustedIssuer == null)
            yield break;

        var keys = secureFetcher.FetchKeysAsync(trustedIssuer.JwksUri, logger, issuer, "software statement issuer");
        await foreach (var key in keys.Where(k => k.Usage is null or PublicKeyUsages.Signature))
        {
            yield return key;
        }
    }
}
