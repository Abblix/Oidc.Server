// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// The principal a cutoff of a scope made of more than one identifier is recorded against.
/// </summary>
internal static class RevocationPrincipal
{
    /// <summary>
    /// The principal of an end user at one client, for <see cref="RevocationScope.ClientSubject"/>.
    /// </summary>
    /// <remarks>
    /// The client identifier goes first with its length, so no pair can spell the same principal as another: a client
    /// identifier and a subject may each hold any character, and joining them with a separator alone would let the
    /// client <c>a:b</c> with the subject <c>c</c> share a cutoff with the client <c>a</c> and the subject <c>b:c</c>.
    /// </remarks>
    public static string ClientSubject(string clientId, string subject) => $"{clientId.Length}:{clientId}:{subject}";
}
