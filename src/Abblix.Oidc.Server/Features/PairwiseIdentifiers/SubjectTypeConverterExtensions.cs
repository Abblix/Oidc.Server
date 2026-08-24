// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.PairwiseIdentifiers;

/// <summary>
/// Comparing a session against the end users a client named.
/// </summary>
public static class SubjectTypeConverterExtensions
{
    /// <summary>
    /// Whether this session belongs to one of the end users named, as the client spells them.
    /// </summary>
    /// <remarks>
    /// OpenID Connect Core 1.0 Section 3.1.2.2 requires this wherever a request names an end user: the server
    /// "MUST NOT reply with an ID Token or Access Token for a different user, even if they have an active
    /// session". Every endpoint accepting such a name needs the same comparison, and one that wrote its own
    /// would have to rediscover both properties below.
    /// <para>
    /// The session is converted forward rather than the name opened, because only the forward direction
    /// answers for a client whose sector moved since the name was minted: opening would fail, while sealing
    /// produces the pseudonym that client would receive today and compares it against what was sent.
    /// </para>
    /// <para>
    /// Neither direction is total. Sealing needs pairwise settings the deployment may not have configured, and
    /// a client registered as pairwise without them makes the converter throw. That is a configuration fault
    /// rather than an answer about this end user, so it is reported as no match: the caller refuses this
    /// session instead of faulting every request that merely named somebody.
    /// </para>
    /// </remarks>
    /// <param name="converter">Seals the session's subject the way this client sees it.</param>
    /// <param name="session">The session to judge.</param>
    /// <param name="subjects">The end users the request will accept. Empty accepts nobody.</param>
    /// <param name="clientInfo">The client whose spelling of a subject is in force.</param>
    public static bool Names(
        this ISubjectTypeConverter converter,
        AuthSession session,
        IReadOnlyCollection<string> subjects,
        ClientInfo clientInfo)
    {
        try
        {
            // Ordinal: a subject is an opaque identifier compared octet for octet, and two that differ only
            // in case are two different end users.
            return subjects.Contains(converter.Convert(session.Subject, clientInfo), StringComparer.Ordinal);
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }
}
