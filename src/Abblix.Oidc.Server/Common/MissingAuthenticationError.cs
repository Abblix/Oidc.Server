// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
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
/// Subtype of <see cref="OidcError"/> tagging a request to a protected endpoint that carried no
/// authentication information at all. RFC 6750 §3.1: in that case the challenge SHOULD NOT include
/// an error code or other error attributes — a bare <c>WWW-Authenticate</c> header simply tells
/// the client that authentication is required. The error code still drives the internal 401
/// status-code mapping; only the challenge attributes are suppressed by the builder. Mirrors
/// <see cref="InvalidDPoPProofError"/> as a typed marker for deterministic pattern matching.
/// </summary>
public sealed record MissingAuthenticationError(string Description)
    : OidcError(ErrorCodes.InvalidToken, Description);
