// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Hands out the fingerprints that stand for credentials in this server's log records.
/// </summary>
/// <remarks>
/// Under <see cref="OidcOptions.LogFingerprintKey"/> when the deployment sets one, so every node and every restart
/// writes the same fingerprint for the same code and the records of one flow can be followed across them. Without it
/// the key is drawn once per process: records still match within one process, and nothing has to be kept secret.
/// </remarks>
/// <param name="options">The server settings that may hold the key.</param>
public sealed class CredentialFingerprints(IOptions<OidcOptions> options)
{
    private readonly byte[] _key = options.Value.LogFingerprintKey is { } configured
        ? Convert.FromBase64String(configured)
        : RandomNumberGenerator.GetBytes(LogFingerprintKeyValidator.MinKeyBytes);

    /// <summary>
    /// The fingerprint that stands for <paramref name="credential"/> in a log record.
    /// </summary>
    public Fingerprint Of(string? credential) => new(_key, credential);
}
