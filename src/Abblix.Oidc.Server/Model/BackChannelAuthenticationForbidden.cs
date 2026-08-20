// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents a forbidden response for a backchannel authentication request.
/// This response typically indicates that the client is authenticated but does not have permission
/// to perform the requested operation.
/// </summary>
/// <param name="Error">The error code that identifies the type of failure.</param>
/// <param name="ErrorDescription">
/// A human-readable description of the error, providing more details about the failure.</param>
public record BackChannelAuthenticationForbidden(string Error, string ErrorDescription)
    : OidcError(Error, ErrorDescription);
