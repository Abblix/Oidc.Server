// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// <see cref="ProfiledJwtIssuer"/> refused to issue a token because the security profile in force does not admit its
/// signature or key management algorithm.
/// </summary>
/// <remarks>
/// Carries what was refused, so a path that chose the algorithm from a key a party published can answer that party's
/// request instead of failing as the server.
/// </remarks>
public sealed class AlgorithmRefusedByProfileException : InvalidOperationException
{
    /// <summary>
    /// Creates the refusal.
    /// </summary>
    /// <param name="message">What was refused, for the log.</param>
    /// <param name="algorithm">The algorithm the profile does not admit.</param>
    /// <param name="encryptionKey">The key the token would have been encrypted to, where the refused algorithm is
    /// its key management algorithm; null where it is the signature algorithm.</param>
    public AlgorithmRefusedByProfileException(string message, string? algorithm, JsonWebKey? encryptionKey)
        : base(message)
    {
        Algorithm = algorithm;
        EncryptionKey = encryptionKey;
    }

    /// <summary>
    /// The algorithm the profile does not admit, null where the token named none.
    /// </summary>
    public string? Algorithm { get; }

    /// <summary>
    /// The key the token would have been encrypted to, where the refused algorithm is its key management algorithm.
    /// </summary>
    public JsonWebKey? EncryptionKey { get; }
}
