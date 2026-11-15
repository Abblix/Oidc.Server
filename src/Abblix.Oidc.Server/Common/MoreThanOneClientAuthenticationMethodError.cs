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
/// Subtype of <see cref="OidcError"/> tagging a request in which more than one client authenticator found a credential
/// of a form it reads, so the request uses more than one client authentication method at once. RFC 6749 section 2.3:
/// "The client MUST NOT use more than one authentication method in each request", and section 5.2 names a request that
/// "includes multiple credentials, utilizes more than one mechanism for authenticating the client" an
/// <c>invalid_request</c>, answered with HTTP 400. Every endpoint authenticating a client answers it as it is, rather
/// than as the <c>invalid_client</c> a failed authentication is.
/// </summary>
public sealed record MoreThanOneClientAuthenticationMethodError(string ErrorDescription)
    : OidcError(ErrorCodes.InvalidRequest, ErrorDescription);
