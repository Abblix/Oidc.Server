// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses at startup a <see cref="OidcOptions.LogFingerprintKey"/> that cannot key the fingerprints of credentials.
/// </summary>
public sealed class LogFingerprintKeyValidator : IValidateOptions<OidcOptions>
{
    /// <summary>
    /// The least decoded length of the key: 256 bits, so the fingerprint of a short code cannot be searched for by
    /// guessing the key instead.
    /// </summary>
    public const int MinKeyBytes = 32;

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        if (options.LogFingerprintKey is not { } key)
            return ValidateOptionsResult.Success;

        var buffer = new byte[key.Length];
        if (!Convert.TryFromBase64String(key, buffer, out var length))
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.LogFingerprintKey)} is not valid base64.");
        }

        if (length < MinKeyBytes)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.LogFingerprintKey)} decodes to {length} bytes; it must carry at least " +
                $"{MinKeyBytes}.");
        }

        return ValidateOptionsResult.Success;
    }
}
