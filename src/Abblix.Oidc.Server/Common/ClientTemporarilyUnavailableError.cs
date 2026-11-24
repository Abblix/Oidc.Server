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
/// Subtype of <see cref="OidcError"/> that refuses a request whose client could not be authenticated because the
/// client metadata document of the client it names could not be had for now, and no valid copy of it is held. It
/// travels out as HTTP 503 with no body, as draft-ietf-oauth-client-id-metadata-document-03 section 6.1 has the token
/// and pushed authorization request endpoints answer "for a transient failure, an HTTP 503 status code".
/// </summary>
/// <remarks>
/// Experimental: it implements an Internet-Draft and may change with the final specification. The status carries the
/// whole answer: no OAuth error code of the token endpoint describes it, and the draft names only the status. No
/// <c>Retry-After</c> is sent, since nothing says when the client's server will answer again. The code and the
/// description never reach a caller; a host reads them if it decorates the endpoint.
/// </remarks>
/// <param name="ErrorDescription">Why the request was refused.</param>
public sealed record ClientTemporarilyUnavailableError(string ErrorDescription)
    : OidcError(ErrorCodes.TemporarilyUnavailable, ErrorDescription);
