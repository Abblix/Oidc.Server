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
using Abblix.Jwt.Encryption;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Fails loud at startup when a configured encryption key has no private material - an external key, whose
/// private half lives with a custodian - but no key-management port is registered to serve it, or when its
/// algorithm has no external form. Signing keys are not checked here: under the decoration model an external
/// signer is not startup-introspectable, so a public-only signing key with no external signer fails closed
/// at runtime on the first sign instead. A purely local configuration, where every key carries its secret
/// material, is unaffected and validates with no external port registered.
/// </summary>
/// <param name="externalKeyEncryptor">The key-management port, or null when the host registered none.</param>
public sealed class ExternalKeyWiringValidator(
    IExternalKeyEncryptor? externalKeyEncryptor = null) : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var failures = new List<string>();

        // Signing keys are intentionally not checked here: with the decoration model there is no
        // startup-introspectable "is an external signer registered" signal, so a public-only signing key
        // with no external signer wired fails closed at runtime (the signing seam throws on the first sign).

        foreach (var key in options.EncryptionKeys)
        {
            // The server's encryption keys decrypt inbound JWE (request objects, service tokens), which needs
            // the private half; a public-only key routes that to the external custodian.
            if (key.HasPrivateKey)
                continue;

            if (externalKeyEncryptor is null)
            {
                failures.Add(
                    $"Encryption key (kid={key.KeyId}) has no private material, so it can only decrypt through " +
                    $"an external key custodian, but no {nameof(IExternalKeyEncryptor)} is registered.");
            }

            if (HasNoExternalForm(key.Algorithm))
            {
                failures.Add(
                    $"Encryption key (kid={key.KeyId}) is external but its algorithm '{key.Algorithm}' has no " +
                    $"external form (direct and password-based key management cannot be externalised).");
            }
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    /// <summary>
    /// Direct encryption (dir) and password-based key management (PBES2) have no external form: the CEK is
    /// the secret itself, or is derived from it by a password KDF, so an external key configured for one of
    /// them can never be served remotely. Mirrors the router's fail-closed decision for these algorithms.
    /// </summary>
    private static bool HasNoExternalForm(string? algorithm) => algorithm switch
    {
        EncryptionAlgorithms.KeyManagement.Dir or
        EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW or
        EncryptionAlgorithms.KeyManagement.Pbes2HmacSha384Aes192KW or
        EncryptionAlgorithms.KeyManagement.Pbes2HmacSha512Aes256KW => true,
        _ => false,
    };
}
