// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// The two ways <see cref="IClientAuthenticator.TryAuthenticateClientAsync"/> answers a request it does not
/// authenticate, both <c>invalid_client</c> (RFC 6749 section 5.2) and told apart by their type.
/// </summary>
public static class ClientAuthenticationFailures
{
    /// <summary>
    /// The request presents no credential of a form the authenticator reads.
    /// </summary>
    public static OidcError NoCredential { get; } =
        new UnauthenticatedCallerError("The request presents no client credential");

    /// <summary>
    /// The request presents a credential of a form the authenticator reads, and it does not authenticate a client.
    /// </summary>
    public static OidcError InvalidCredential { get; } =
        new(ErrorCodes.InvalidClient, "The client credential does not authenticate a client");
}
