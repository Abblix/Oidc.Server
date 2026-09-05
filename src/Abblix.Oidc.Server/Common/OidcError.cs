// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Represents an error that occurred during OAuth 2.0/OpenID Connect request processing.
/// </summary>
/// <param name="Error">The error code indicating the nature of the error.</param>
/// <param name="ErrorDescription">A human-readable description of the error.</param>
public record OidcError(string Error, string ErrorDescription);
