// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
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
/// <remarks>
/// Whether a tenant has a key to encrypt with, where a token type asks for encryption, is judged per tenant by
/// <see cref="ServiceTokenEncryptionKeysCheck"/>.
/// </remarks>
public sealed class ServiceTokensAlgorithmsValidator(IJsonWebTokenCreator jwtCreator) : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var check = new ServiceTokenCheck(
            jwtCreator.SignedResponseAlgorithmsSupported.ToHashSet(StringComparer.Ordinal),
            jwtCreator.EncryptedResponseAlgorithmsSupported.ToHashSet(StringComparer.Ordinal));

        var serviceTokens = options.ServiceTokens;
        var failures = new List<string>();
        failures.AddRange(check.Failures(nameof(serviceTokens.AccessToken), serviceTokens.AccessToken));
        failures.AddRange(check.Failures(nameof(serviceTokens.RefreshToken), serviceTokens.RefreshToken));
        failures.AddRange(check.Failures(
            nameof(serviceTokens.RegistrationAccessToken),
            serviceTokens.RegistrationAccessToken));
        failures.AddRange(check.Failures(nameof(serviceTokens.InitialAccessToken), serviceTokens.InitialAccessToken));

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    /// <summary>
    /// What one validation run settles before it looks at any token, applied to each token in turn.
    /// </summary>
    /// <remarks>
    /// Method Object: the per-token rules share the algorithm sets and the key verdict that
    /// <see cref="Validate"/> computes once, so they sit on one object rather than in a closure over its locals.
    /// </remarks>
    /// <param name="SigningAlgorithms">The signing algorithms the registered signers produce.</param>
    /// <param name="KeyManagementAlgorithms">The JWE key-management algorithms the registered encryptors
    /// produce.</param>
    private sealed record ServiceTokenCheck(
        HashSet<string> SigningAlgorithms,
        HashSet<string> KeyManagementAlgorithms)
    {
        public IEnumerable<string> Failures(string tokenType, ServiceTokenOptions token)
        {
            var signingAlgorithm = token.Signing.Algorithm;
            if (!SigningAlgorithms.Contains(signingAlgorithm))
            {
                yield return
                    $"ServiceTokens.{tokenType}.Signing.Algorithm '{signingAlgorithm}' is not among the " +
                    $"registered signing algorithms ({string.Join(", ", SigningAlgorithms)}).";
            }

            if (token.Encrypt == false)
                yield break;

            var encryptionAlgorithm = token.Encryption.Algorithm;
            if (encryptionAlgorithm is not null && !KeyManagementAlgorithms.Contains(encryptionAlgorithm))
            {
                yield return
                    $"ServiceTokens.{tokenType}.Encryption.Algorithm '{encryptionAlgorithm}' is not among the " +
                    $"registered JWE key-management algorithms ({string.Join(", ", KeyManagementAlgorithms)}).";
            }
        }
    }
}
