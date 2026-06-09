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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Builds <see cref="OidcError"/> instances using the error codes RFC 7591 §3.2.2 reserves
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
