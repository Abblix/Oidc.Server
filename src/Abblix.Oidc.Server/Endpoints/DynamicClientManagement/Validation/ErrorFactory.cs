// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Builds <see cref="OidcError"/> instances using the error codes RFC 7591 section 3.2.2 reserves
/// for dynamic client registration: <c>invalid_redirect_uri</c>, <c>invalid_client_metadata</c>,
/// <c>invalid_software_statement</c>, and <c>unapproved_software_statement</c>.
/// </summary>
public static class ErrorFactory
{
    /// <summary>
    /// Creates a validation error for an invalid redirect URI.
    /// </summary>
    /// <param name="description">The description of the error.</param>
    /// <returns>An error instance with the error code and description.</returns>
    public static OidcError InvalidRedirectUri(string description)
        => new(ErrorCodes.InvalidRedirectUri, description);

    /// <summary>
    /// Creates a validation error for invalid client metadata.
    /// </summary>
    /// <param name="description">The description of the error.</param>
    /// <returns>An error instance with the error code and description.</returns>
    public static OidcError InvalidClientMetadata(string description)
        => new(ErrorCodes.InvalidClientMetadata, description);

    /// <summary>
    /// Creates a validation error for an invalid software statement per RFC 7591 Section 3.2.2.
    /// </summary>
    /// <param name="description">The description of the error.</param>
    /// <returns>An error instance with the error code and description.</returns>
    public static OidcError InvalidSoftwareStatement(string description)
        => new(ErrorCodes.InvalidSoftwareStatement, description);

    /// <summary>
    /// Creates a validation error for an unapproved software statement per RFC 7591 Section 3.2.2.
    /// </summary>
    /// <param name="description">The description of the error.</param>
    /// <returns>An error instance with the error code and description.</returns>
    public static OidcError UnapprovedSoftwareStatement(string description)
        => new(ErrorCodes.UnapprovedSoftwareStatement, description);
}
