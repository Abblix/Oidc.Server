// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Subtype of <see cref="OidcError"/> tagging a request to a protected endpoint that carried no
/// authentication information at all. RFC 6750 §3.1: in that case the challenge SHOULD NOT include
/// an error code or other error attributes - a bare <c>WWW-Authenticate</c> header simply tells
/// the client that authentication is required. The error code still drives the internal 401
/// status-code mapping; only the challenge attributes are suppressed by the builder. Mirrors
/// <see cref="InvalidDPoPProofError"/> as a typed marker for deterministic pattern matching.
/// </summary>
public sealed record MissingAuthenticationError(string Description)
    : OidcError(ErrorCodes.InvalidToken, Description);
