// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Fails loudly at startup when a configured <see cref="ServiceTokensOptions"/> names a signing or
/// key-management algorithm that no registered signer or encryptor can produce, instead of letting the
/// contradiction surface at token-issuance time as a per-request failure. The accepted sets are read from
/// the live JWT registrations, the same union OpenID Connect discovery advertises, so a host that adds or
/// replaces an algorithm is validated against exactly what it registered - no static allow-list to keep in sync.
/// </summary>
/// <param name="jwtCreator">Source of the registered signing and JWE key-management algorithms. Kept
/// lightweight on purpose, so validating options does not drag the runtime token pipeline (and its storage)
/// into startup.</param>
/// <param name="custodian">Present when the host holds its keys in an external custodian (a Vault or Key Vault
/// backend), absent when they come from <see cref="OidcOptions.EncryptionKeys"/>. It is a registration marker
/// only, and is never called here: it answers where the keys come from without reading them, and without
/// reading the options that are still being created. Injecting the key provider instead would re-enter
/// <see cref="IOptions{TOptions}.Value"/> from inside its own creation.</param>
/// <param name="services">Tells whether the server serves tenants, whose own settings carry no keys while each
/// tenant's carry its own.</param>
public sealed class ServiceTokensAlgorithmsValidator(
    IJsonWebTokenCreator jwtCreator,
    IKeyCustodian? custodian = null,
    IServiceProvider? services = null) : IValidateOptions<OidcOptions>
{
    private static string NoEncryptionKey(string tokenType, string keysSetting)
        => $"ServiceTokens.{tokenType}.Encrypt is true, but no encryption key is available: " +
           $"{keysSetting} is empty and no external key custodian is registered. " +
           $"Configure an encryption key, or set ServiceTokens.{tokenType}.Encrypt to false to issue " +
           $"this token as a signed JWS.";

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var signingAlgorithms = jwtCreator.SignedResponseAlgorithmsSupported.ToHashSet(StringComparer.Ordinal);
        var keyManagementAlgorithms = jwtCreator.EncryptedResponseAlgorithmsSupported.ToHashSet(StringComparer.Ordinal);

        var failures = new List<string>();
        var serviceTokens = options.ServiceTokens;

        // Under multi-tenancy the server's own settings carry no keys and each tenant's carry its own
        var ofTenant = MultiTenancyDetection.IsTenantsOwn(options);
        var keysJudgedHere = custodian is null &&
                             (ofTenant || services is null || !MultiTenancyDetection.IsActive(services));
#pragma warning disable ABXMT001
        var keysSetting = ofTenant
            ? $"{nameof(TenantDefinition)}.{nameof(TenantDefinition.EncryptionKeys)}"
            : $"{nameof(OidcOptions)}.{nameof(OidcOptions.EncryptionKeys)}";
#pragma warning restore ABXMT001

        Check(failures, nameof(serviceTokens.AccessToken), serviceTokens.AccessToken);
        Check(failures, nameof(serviceTokens.RefreshToken), serviceTokens.RefreshToken);
        Check(failures, nameof(serviceTokens.RegistrationAccessToken), serviceTokens.RegistrationAccessToken);
        Check(failures, nameof(serviceTokens.InitialAccessToken), serviceTokens.InitialAccessToken);

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);

        void Check(List<string> results, string tokenType, ServiceTokenOptions token)
        {
            var signingAlgorithm = token.Signing.Algorithm;
            if (!signingAlgorithms.Contains(signingAlgorithm))
            {
                results.Add(
                    $"ServiceTokens.{tokenType}.Signing.Algorithm '{signingAlgorithm}' is not among the " +
                    $"registered signing algorithms ({string.Join(", ", signingAlgorithms)}).");
            }

            if (token.Encrypt == false)
                return;

            var encryptionAlgorithm = token.Encryption.Algorithm;
            if (encryptionAlgorithm is not null && !keyManagementAlgorithms.Contains(encryptionAlgorithm))
            {
                results.Add(
                    $"ServiceTokens.{tokenType}.Encryption.Algorithm '{encryptionAlgorithm}' is not among the " +
                    $"registered JWE key-management algorithms ({string.Join(", ", keyManagementAlgorithms)}).");
            }

            // Asked to encrypt with nothing to encrypt with. Only an explicit true is refused: the null default
            // states nothing, and a host that never touched the setting must keep starting and issuing a signed
            // JWS exactly as before. The key set is only knowable here when it comes from the options; with a
            // custodian registered the keys live outside them, so the emptiness above says nothing.
            if (token.Encrypt == true && keysJudgedHere && options.EncryptionKeys.Count == 0)
                results.Add(NoEncryptionKey(tokenType, keysSetting));
        }
    }
}
