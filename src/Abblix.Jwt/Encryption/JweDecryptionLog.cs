// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Frozen;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// Records an inbound JWE that no key opened, which its sender only learns of as a refusal.
/// </summary>
/// <remarks>
/// The token's header is the sender's text. A key management algorithm this server does not register is not
/// written at all, and the key identifier is written through <see cref="Sanitized"/>, as every value a sender chose
/// is. The content encryption algorithm needs neither, since a token naming one this server does not register is
/// refused before any key is tried.
/// </remarks>
/// <param name="logger">The log the record goes to.</param>
/// <param name="algorithms">The key management algorithms this server registers.</param>
internal sealed partial class JweDecryptionLog(
    ILogger<JweDecryptionLog> logger,
    EncryptionAlgorithmsProvider algorithms)
{
    private const string UnregisteredAlgorithm = "(unregistered)";

    // Read once: the registrations are fixed when the container is built, and a flood of forged tokens would
    // otherwise enumerate them on every refusal.
    private readonly FrozenSet<string> _registeredAlgorithms =
        algorithms.KeyManagementAlgorithms.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>
    /// No key was a candidate for the token.
    /// </summary>
    public void NoDecryptionKey(JweEnvelope envelope)
        => LogNoDecryptionKey(Algorithm(envelope), envelope.EncryptionAlgorithm, envelope.Header.KeyId);

    /// <summary>
    /// None of <paramref name="keysTried"/> candidate keys opened the token.
    /// </summary>
    public void NoKeyOpened(JweEnvelope envelope, int keysTried)
        => LogNoKeyOpened(Algorithm(envelope), envelope.EncryptionAlgorithm, envelope.Header.KeyId, keysTried);

    private string Algorithm(JweEnvelope envelope)
        => _registeredAlgorithms.Contains(envelope.Algorithm)
            ? envelope.Algorithm
            : UnregisteredAlgorithm;
}
