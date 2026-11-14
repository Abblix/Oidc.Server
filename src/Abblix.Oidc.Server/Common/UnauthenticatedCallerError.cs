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
/// Subtype of <see cref="OidcError"/> tagging a request that does not authenticate the caller: one in which no client
/// authenticator found a credential of a form it reads (the answer of
/// <see cref="Features.ClientAuthentication.IClientAuthenticator.TryAuthenticateClientAsync"/> for it), and at the
/// introspection endpoint a public client (token endpoint authentication method <c>none</c>), whose client_id alone
/// proves nothing. The introspection endpoint answers it with HTTP 400, RFC 9701 section 5: "An AS compliant with this
/// specification MUST refuse to serve introspection requests that don't authenticate the caller and return an HTTP
/// status code 400"; the other endpoints answer it as the invalid_client it is. The code is
/// <c>invalid_client</c>, which RFC 6749 section 5.2 defines for "no client authentication included". A credential that
/// was presented and failed is a plain <c>invalid_client</c> instead, answered 401 as RFC 7662 section 2.3 has it.
/// </summary>
public sealed record UnauthenticatedCallerError(string ErrorDescription)
    : OidcError(ErrorCodes.InvalidClient, ErrorDescription);
