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
/// Subtype of <see cref="OidcError"/> tagging an <c>invalid_request</c> about how a request to an endpoint protected by
/// a Bearer token alone included that token, such as the client configuration endpoint (RFC 7592 section 2.1) and a
/// registration endpoint requiring an initial access token (RFC 7591 section 3.2.2). RFC 6750 section 3 has the
/// resource server "MUST include the HTTP "WWW-Authenticate" response header field" when the request "does not contain
/// an access token that enables access", so the answer carries a Bearer challenge with the error, where the same code
/// from an endpoint authenticating the client carries none. Mirrors <see cref="MissingAuthenticationError"/> as a typed
/// marker for deterministic pattern matching.
/// </summary>
public sealed record BearerRequestError(string ErrorDescription)
    : OidcError(ErrorCodes.InvalidRequest, ErrorDescription);
