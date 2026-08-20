// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
