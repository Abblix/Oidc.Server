// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Persists a new client and constructs the RFC 7591 section 3.2.1 success response from a request
/// whose metadata has already been validated. Generates credentials and the
/// <c>registration_access_token</c> bound to the new <c>client_id</c>.
/// </summary>
public interface IRegisterClientRequestProcessor
{
    /// <summary>
    /// Stores the validated client and returns the registration response payload.
    /// </summary>
    /// <param name="request">The validated registration request.</param>
    Task<Result<ClientRegistrationSuccessResponse, OidcError>> ProcessAsync(ValidClientRegistrationRequest request);
}
