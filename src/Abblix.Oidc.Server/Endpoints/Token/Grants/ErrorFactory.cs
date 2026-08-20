// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Builds <see cref="OidcError"/> instances using the error codes RFC 6749 §5.2 defines for
/// the token endpoint. Mirrors the sibling per-area factories (authorization validation,
/// dynamic client registration, secure HTTP fetch): each area exposes only the error codes
/// its specification legitimately uses, so codes from one protocol surface do not leak into
/// another.
/// </summary>
public static class ErrorFactory
{
    /// <summary>
    /// Creates an error for a malformed token request - a missing, repeated, or otherwise
    /// invalid parameter (RFC 6749 §5.2, <c>invalid_request</c>).
    /// </summary>
    /// <param name="description">The description of the error.</param>
    /// <returns>An error instance with the error code and description.</returns>
    public static OidcError InvalidRequest(string description)
        => new(ErrorCodes.InvalidRequest, description);

    /// <summary>
    /// Creates an error for a token request whose required parameter is absent
    /// (RFC 6749 §5.2, <c>invalid_request</c>).
    /// </summary>
    /// <param name="parameterName">The wire-level name of the missing parameter.</param>
    /// <returns>An error instance with the error code and description.</returns>
    public static OidcError MissingParameter(string parameterName)
        => InvalidRequest($"The {parameterName} parameter is required");
}
