// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.PairwiseIdentifiers;

/// <summary>
/// Seals and opens every party a token names, the subject and each actor alike, for a client's sector.
/// </summary>
/// <remarks>
/// The server keeps the real identifiers of all parties, in a grant and in storage, and a client sees them only on
/// the wire, in the token issued to it. Every token service seals through here and every reader opens through here,
/// so no party of a token is converted apart from the others: an actor sealed while the subject is not, or opened
/// while the subject is, would be one party seen under two identifiers.
/// </remarks>
internal static class TokenSubjectsConversion
{
    /// <summary>
    /// Replaces the real parties <paramref name="payload"/> names with the identifiers <paramref name="client"/>
    /// sees for them.
    /// </summary>
    public static void SealSubjects(
        this ISubjectTypeConverter converter,
        TenantDefinition tenant,
        JsonWebTokenPayload payload,
        ClientInfo client)
        => converter.Seal(tenant, TokenSubjects.Of(payload), client).WriteTo(payload);

    /// <summary>
    /// The identifiers <paramref name="client"/> sees for the real parties <paramref name="real"/> names.
    /// </summary>
    public static TokenSubjects Seal(
        this ISubjectTypeConverter converter,
        TenantDefinition tenant,
        TokenSubjects real,
        ClientInfo client)
    {
        string Convert(string subject) => converter.Convert(tenant, subject, client);

        return new TokenSubjects(
            Convert(real.Subject),
            real.Actor is null ? null : MapActor(real.Actor, Convert).NotNull(nameof(real.Actor)));
    }

    /// <summary>
    /// The real parties behind the identifiers <paramref name="client"/> sees, or <c>null</c> when any of them does
    /// not open for its sector.
    /// </summary>
    /// <remarks>
    /// One party that does not open leaves the token naming somebody unknown, so the whole answer is withheld rather
    /// than a partial chain returned.
    /// </remarks>
    public static TokenSubjects? Open(
        this ISubjectTypeConverter converter,
        TenantDefinition tenant,
        TokenSubjects seen,
        ClientInfo client)
    {
        string? ConvertBack(string subject) => converter.ConvertBack(tenant, subject, client);

        if (ConvertBack(seen.Subject) is not { } subject)
            return null;

        if (seen.Actor is null)
            return new TokenSubjects(subject, null);

        return MapActor(seen.Actor, ConvertBack) is { } actor
            ? new TokenSubjects(subject, actor)
            : null;
    }

    /// <summary>
    /// A copy of <paramref name="actor"/> with the <c>sub</c> of every actor in the chain converted, or <c>null</c>
    /// when one does not convert.
    /// </summary>
    private static JsonObject? MapActor(JsonObject actor, Func<string, string?> convert)
    {
        var mapped = new JsonObject();
        foreach (var (name, value) in actor)
        {
            switch (name)
            {
                case IanaClaimTypes.Sub when value is JsonValue sub && sub.TryGetValue<string>(out var identifier):
                    if (convert(identifier) is not { } converted)
                        return null;

                    mapped[name] = converted;
                    break;

                case IanaClaimTypes.Act when value is JsonObject prior:
                    if (MapActor(prior, convert) is not { } priorMapped)
                        return null;

                    mapped[name] = priorMapped;
                    break;

                default:
                    mapped[name] = value?.DeepClone();
                    break;
            }
        }

        return mapped;
    }
}
