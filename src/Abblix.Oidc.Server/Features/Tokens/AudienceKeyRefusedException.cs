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
/// An access token was not issued because the encryption key its audience publishes would have it encrypted with a
/// key management algorithm the security profile in force forbids.
/// </summary>
/// <remarks>
/// The refusal belongs to the resource the request named rather than to the server, so the token endpoint answers it
/// as an unusable resource (RFC 8707 section 2, <c>invalid_target</c>).
/// </remarks>
public sealed class AudienceKeyRefusedException : InvalidOperationException
{
    /// <summary>
    /// Creates the refusal from the one <see cref="ProfiledJwtIssuer"/> raised.
    /// </summary>
    /// <param name="resources">The resources the access token was for.</param>
    /// <param name="refusal">The issuer's refusal of the key management algorithm.</param>
    public AudienceKeyRefusedException(IReadOnlyCollection<Uri> resources, AlgorithmRefusedByProfileException refusal)
        : base(refusal.Message, refusal)
    {
        Resources = resources;
        Algorithm = refusal.Algorithm;
    }

    /// <summary>
    /// The resources the access token was for, one of which publishes the key.
    /// </summary>
    public IReadOnlyCollection<Uri> Resources { get; }

    /// <summary>
    /// The key management algorithm the profile forbids.
    /// </summary>
    public string? Algorithm { get; }
}
