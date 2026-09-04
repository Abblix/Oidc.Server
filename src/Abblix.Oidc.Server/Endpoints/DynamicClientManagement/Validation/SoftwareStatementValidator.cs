// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the software_statement parameter in a client registration request per RFC 7591 Section 2.3.
/// Software statements are signed JWTs issued by a third-party authority asserting metadata about client software.
/// </summary>
/// <param name="logger">Logger for recording validation operations.</param>
/// <param name="jwtValidator">Validates the software statement JWT signature and claims.</param>
/// <param name="options">OIDC options containing software statement configuration.</param>
/// <param name="secureFetcher">HTTP fetcher with SSRF protection for retrieving trusted issuer JWKS.</param>
public partial class SoftwareStatementValidator(
    ILogger<SoftwareStatementValidator> logger,
    IJsonWebTokenValidator jwtValidator,
    IOptionsMonitor<OidcOptions> options,
    [FromKeyedServices(KeySetOwners.SoftwareStatementIssuer)] ISecureHttpFetcher secureFetcher)
    : IClientRegistrationContextValidator
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
            // Skip audience - software statements describe the software, not target a specific server
            MaxClockOffsetAhead = SecurityProfileRequirements
                .Resolve(options.CurrentValue.DefaultSecurityProfile).MaxClockOffsetAhead,

            Options = ValidationOptions.Default &
                      ~ValidationOptions.RequireAudience &
                      ~ValidationOptions.ValidateAudience,

            ValidateIssuer = issuer => ValidateIssuer(softwareStatementOptions, issuer),
            ResolveIssuerSigningKeys = issuer => ResolveSigningKeysAsync(softwareStatementOptions, issuer),
        };

        var result = await jwtValidator.ValidateAsync(softwareStatement, validationParameters);

        if (result.TryGetFailure(out var error))
        {
            LogValidationFailed(error.ErrorDescription);
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
            LogIssuerNotTrusted(issuer);
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
            ti => ti.Issuer == issuer);
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

        var keys = secureFetcher.FetchKeysAsync(
            trustedIssuer.JwksUri, logger, issuer, KeySetOwners.SoftwareStatementIssuer);
        await foreach (var key in keys.Where(k => k.Usage is null or PublicKeyUsages.Signature))
        {
            yield return key;
        }
    }
}
