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
/// Subtype of <see cref="OidcError"/> tagging an introspection request that does not authenticate the caller, which
/// RFC 9701 section 5 has the server refuse with HTTP 400: "An AS compliant with this specification MUST refuse to
/// serve introspection requests that don't authenticate the caller and return an HTTP status code 400". Returned for a
/// request carrying no client credential at all, and for a public client (token endpoint authentication method
/// <c>none</c>), whose client_id alone the authenticator accepts but which proves nothing. The code is
/// <c>invalid_client</c>, which RFC 6749 section 5.2 defines for "no client authentication included". A credential that
/// was presented and failed is a plain <c>invalid_client</c> instead, answered 401 as RFC 7662 section 2.3 has it.
/// </summary>
public sealed record UnauthenticatedCallerError(string ErrorDescription)
    : OidcError(ErrorCodes.InvalidClient, ErrorDescription);
