// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Produces unique, unguessable request URIs used to reference stored authorization request objects,
/// such as those handled by Pushed Authorization Requests (RFC 9126) via the <c>request_uri</c> parameter.
/// Implementations must derive the URI from a high-entropy, cryptographically secure random value to prevent
/// an attacker from guessing or enumerating active authorization requests.
/// </summary>
public interface IAuthorizationRequestUriGenerator
{
    /// <summary>
    /// Generates a unique, unpredictable URI suitable for use as the <c>request_uri</c> reference for a
    /// previously stored authorization request.
    /// </summary>
    /// <returns>A unique URI that serves as the identifier for a specific authorization request.</returns>
    Uri GenerateRequestUri();
}
