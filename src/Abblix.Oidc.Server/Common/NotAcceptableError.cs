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
/// Subtype of <see cref="OidcError"/> tagging a request whose <c>Accept</c> header names a representation this server
/// cannot produce for it, answered with HTTP 406 (RFC 9110 section 15.5.7): the resource "does not have a current
/// representation that would be acceptable to the user agent, according to the proactive negotiation header fields
/// received in the request". The error code is the generic <c>invalid_request</c>, since neither RFC 6749 nor RFC 7662
/// nor RFC 9701 defines one for it; the status is what tells the caller.
/// </summary>
public sealed record NotAcceptableError(string ErrorDescription)
    : OidcError(ErrorCodes.InvalidRequest, ErrorDescription);
