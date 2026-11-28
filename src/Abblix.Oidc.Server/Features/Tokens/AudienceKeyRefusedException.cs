// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Tokens.Formatters;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// An access token was not issued because it cannot be encrypted to its audience: none of the encryption keys a resource
/// publishes is one a token can be encrypted to (under an algorithm this server performs, that the key's material
/// carries out, and that the security profile in force admits), or several of its resources each publish one while an
/// encrypted token has a single recipient.
/// </summary>
/// <remarks>
/// The refusal belongs to the resource the request named rather than to the server, so the token endpoint answers it
/// as an unusable resource (RFC 8707 section 2, <c>invalid_target</c>).
/// </remarks>
public sealed class AudienceKeyRefusedException : InvalidOperationException
{
    /// <summary>
    /// Creates the refusal of a token that cannot be encrypted to its audience.
    /// </summary>
    /// <param name="resources">The resources refused: the one whose keys a token cannot be encrypted to, or those
    /// each publishing a key.</param>
    /// <param name="defaultAlgorithm">The key management algorithm a key declaring none was judged under.</param>
    /// <param name="message">What was refused, naming the resource.</param>
    public AudienceKeyRefusedException(IReadOnlyCollection<Uri> resources, string defaultAlgorithm, string message)
        : base(message)
    {
        Resources = resources;
        DefaultAlgorithm = defaultAlgorithm;
    }

    /// <summary>
    /// The key management algorithm a key declaring none was judged under: the server's own setting for the token,
    /// else the library's default, which a refusal of such a key may come from rather than from the key.
    /// </summary>
    public string DefaultAlgorithm { get; }

    /// <summary>
    /// The resources refused: the one whose keys a token cannot be encrypted to, or those each publishing a key.
    /// </summary>
    public IReadOnlyCollection<Uri> Resources { get; }
}
