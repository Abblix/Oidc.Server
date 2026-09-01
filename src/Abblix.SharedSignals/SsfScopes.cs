// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals;

/// <summary>
/// The OAuth scopes governing the Stream Management API.
/// </summary>
/// <remarks>
/// The CAEP Interoperability Profile 1.0 draft 01 Section 2.7.3 defines both and reserves the prefix:
/// "Scopes values beginning with 'ssf.' are reserved and MUST only be defined by the SSF specifications."
/// So this file is a transcription, not a design - a deployment inventing a third <c>ssf.</c> scope is
/// outside the profile whatever it does with it.
/// <para>
/// An authorization server issuing tokens to receivers has to be able to grant these two. This library's
/// own authorization server refuses a scope nobody registered, so a deployment running both declares them
/// alongside its other scopes; nothing here reaches into that side, and nothing there needs to know about
/// Shared Signals.
/// </para>
/// </remarks>
public static class SsfScopes
{
    /// <summary>
    /// Reading, and nothing else: "The ssf.read scope allows Read Stream Configuration and Get Stream
    /// Status operations."
    /// </summary>
    public const string Read = "ssf.read";

    /// <summary>
    /// Reading plus changing: "The ssf.manage scope includes all ssf.read permissions and additionally
    /// allows Create Stream, Delete Stream, and Stream Verification operations."
    /// </summary>
    /// <remarks>
    /// A caller holding this holds <see cref="Read"/> as well, by that sentence, so a check for read
    /// access is satisfied by either.
    /// </remarks>
    public const string Manage = "ssf.manage";

    /// <summary>
    /// Whether <paramref name="granted"/> satisfies <paramref name="required"/>, with the inclusion the
    /// profile states: <see cref="Manage"/> covers <see cref="Read"/>, and not the other way round.
    /// </summary>
    public static bool Satisfies(IEnumerable<string> granted, string required)
        => granted.Any(scope => scope == required || (required == Read && scope == Manage));
}
