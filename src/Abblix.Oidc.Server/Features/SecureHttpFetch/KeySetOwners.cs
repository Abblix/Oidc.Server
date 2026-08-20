// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// The kinds of party whose key set this server fetches, as they appear in log messages.
/// </summary>
/// <remarks>
/// These are log labels rather than protocol values, so nothing on the wire depends on them. They are named
/// here so that the four call sites agree on their spelling: an operator grepping the log for one kind should
/// not have to guess whether it was written as "software statement issuer" or "software-statement issuer".
/// </remarks>
public static class KeySetOwners
{
    /// <summary>A registered client, whose keys verify its request objects and client assertions.</summary>
    public const string Client = "client";

    /// <summary>A trusted issuer of the assertions accepted by the JWT bearer grant (RFC 7523).</summary>
    public const string Issuer = "issuer";

    /// <summary>The issuer of a software statement presented at dynamic client registration (RFC 7591).</summary>
    public const string SoftwareStatementIssuer = "software statement issuer";

    /// <summary>A protected resource, whose key encrypts the access token issued for it (RFC 9728).</summary>
    public const string Resource = "resource";
}
