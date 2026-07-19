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

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// A static factory class for creating OIDC error instances related to secure HTTP fetching operations.
/// </summary>
public static class ErrorFactory
{
    /// <summary>
    /// Creates a validation error for invalid client metadata.
    /// </summary>
    /// <param name="errorDescription">The description of the error.</param>
    /// <returns>An error instance with the InvalidClientMetadata error code and description.</returns>
    public static OidcError InvalidClientMetadata(string errorDescription)
        => new(ErrorCodes.InvalidClientMetadata, errorDescription);
}
