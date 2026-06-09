// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Subtype of <see cref="OidcError"/> tagging an RFC 9449 §7.1 DPoP proof rejection at a
/// protected endpoint (UserInfo, introspection, revocation). The typed marker lets the
/// response formatter pattern-match deterministically and emit the
/// <c>WWW-Authenticate: DPoP error="invalid_dpop_proof"</c> challenge instead of a Bearer
/// challenge, without string-comparing the error code. Mirrors <see cref="UseDPoPNonceError"/>.
/// </summary>
public sealed record InvalidDPoPProofError(string Description)
    : OidcError(ErrorCodes.InvalidDPoPProof, Description);
