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
/// An access token was not issued because none of the encryption keys its audience publishes is one a token can be
/// encrypted to: under an algorithm this server performs, that the key's material carries out, and that the security
/// profile in force admits.
/// </summary>
/// <remarks>
/// The refusal belongs to the resource the request named rather than to the server, so the token endpoint answers it
/// as an unusable resource (RFC 8707 section 2, <c>invalid_target</c>).
/// </remarks>
public sealed class AudienceKeyRefusedException : InvalidOperationException
{
    /// <summary>
    /// Creates the refusal of a resource that publishes encryption keys, none of which a token can be encrypted to.
    /// </summary>
    /// <param name="resources">The resources the access token was for.</param>
    /// <param name="message">What was refused, naming the resource.</param>
    public AudienceKeyRefusedException(IReadOnlyCollection<Uri> resources, string message)
        : base(message)
    {
        Resources = resources;
    }

    /// <summary>
    /// The resources the access token was for, one of which publishes the key.
    /// </summary>
    public IReadOnlyCollection<Uri> Resources { get; }
}
