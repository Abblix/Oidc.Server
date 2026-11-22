// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.PairwiseIdentifiers;

/// <summary>
/// The parties a token names: the end user in <c>sub</c> and the actors of its RFC 8693 section 4.1 <c>act</c> chain,
/// each the identifier a client sees for that party.
/// </summary>
/// <remarks>
/// They travel together because a pairwise client must see every one of them under its own pseudonym: sealing the
/// subject and leaving an actor real would hand the client the identifier the subject was sealed to hide.
/// </remarks>
/// <param name="Subject">The <c>sub</c> of the token.</param>
/// <param name="Actor">The <c>act</c> of the token, nested actors included, or <c>null</c> when it is not a
/// delegation token.</param>
internal sealed record TokenSubjects(string Subject, JsonObject? Actor)
{
    /// <summary>
    /// The parties <paramref name="payload"/> names, the actor chain detached from it.
    /// </summary>
    public static TokenSubjects Of(JsonWebTokenPayload payload)
        => new(
            payload.Subject.NotNull(nameof(payload.Subject)),
            payload.Json[IanaClaimTypes.Act] is JsonObject act ? (JsonObject)act.DeepClone() : null);

    /// <summary>
    /// Writes these parties into <paramref name="payload"/>, replacing the ones it named.
    /// </summary>
    public void WriteTo(JsonWebTokenPayload payload)
    {
        payload.Subject = Subject;
        if (Actor is null)
            payload.Json.Remove(IanaClaimTypes.Act);
        else
            payload.Json[IanaClaimTypes.Act] = Actor.DeepClone();
    }
}
