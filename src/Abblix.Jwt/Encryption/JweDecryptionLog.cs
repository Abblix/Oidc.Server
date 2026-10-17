// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Frozen;
using Microsoft.Extensions.Logging;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// Records an inbound JWE that no key opened, which its sender only learns of as a refusal.
/// </summary>
/// <remarks>
/// The token's header is the sender's text, so it reaches the record only in a form that cannot pose as another
/// record or flood one: a key management algorithm this server does not register is not written at all, and the key
/// identifier is cut short with its control characters replaced. The content encryption algorithm needs neither,
/// since a token naming one this server does not register is refused before any key is tried.
/// </remarks>
/// <param name="logger">The log the record goes to.</param>
/// <param name="algorithms">The key management algorithms this server registers.</param>
internal sealed partial class JweDecryptionLog(
    ILogger<JweDecryptionLog> logger,
    EncryptionAlgorithmsProvider algorithms)
{
    // Long enough for any key identifier a key ring or a published JWKS gives out, short enough that a crafted one
    // cannot make a record of the request's own size.
    private const int MaxKeyIdLength = 64;

    private const string UnregisteredAlgorithm = "(unregistered)";
    private const char ReplacedControlCharacter = '?';

    // Read once: the registrations are fixed when the container is built, and a flood of forged tokens would
    // otherwise enumerate them on every refusal.
    private readonly FrozenSet<string> _registeredAlgorithms =
        algorithms.KeyManagementAlgorithms.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>
    /// No key was a candidate for the token.
    /// </summary>
    public void NoDecryptionKey(JweEnvelope envelope)
        => LogNoDecryptionKey(Algorithm(envelope), envelope.EncryptionAlgorithm, KeyId(envelope));

    /// <summary>
    /// None of <paramref name="keysTried"/> candidate keys opened the token.
    /// </summary>
    public void NoKeyOpened(JweEnvelope envelope, int keysTried)
        => LogNoKeyOpened(Algorithm(envelope), envelope.EncryptionAlgorithm, KeyId(envelope), keysTried);

    private string Algorithm(JweEnvelope envelope)
        => _registeredAlgorithms.Contains(envelope.Algorithm)
            ? envelope.Algorithm
            : UnregisteredAlgorithm;

    private static string? KeyId(JweEnvelope envelope)
    {
        if (envelope.Header.KeyId is not { } keyId)
            return null;

        var shown = keyId.Length > MaxKeyIdLength ? keyId[..MaxKeyIdLength] : keyId;
        return string.Create(shown.Length, shown, static (target, source) =>
        {
            for (var i = 0; i < source.Length; i++)
                target[i] = char.IsControl(source[i]) ? ReplacedControlCharacter : source[i];
        });
    }
}
