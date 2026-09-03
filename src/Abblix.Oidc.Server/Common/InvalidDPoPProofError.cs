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
/// Subtype of <see cref="OidcError"/> tagging an RFC 9449 section 7.1 DPoP proof rejection at a
/// protected endpoint (UserInfo, introspection, revocation). The typed marker lets the
/// response formatter pattern-match deterministically and emit the
/// <c>WWW-Authenticate: DPoP error="invalid_dpop_proof"</c> challenge instead of a Bearer
/// challenge, without string-comparing the error code. Mirrors <see cref="UseDPoPNonceError"/>.
/// </summary>
public sealed record InvalidDPoPProofError(string Description)
    : OidcError(ErrorCodes.InvalidDPoPProof, Description);
