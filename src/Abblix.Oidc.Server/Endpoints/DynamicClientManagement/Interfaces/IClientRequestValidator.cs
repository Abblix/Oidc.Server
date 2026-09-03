// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Validates a request against the client configuration endpoint (RFC 7592 section 2-section 4).
/// Confirms that the bearer registration access token authorizes the operation on the
/// referenced <c>client_id</c> and that the client still exists.
/// </summary>
public interface IClientRequestValidator
{
    /// <summary>
    /// Validates the request, returning the resolved <see cref="ValidClientRequest"/> on success
    /// or an <see cref="OidcError"/> describing the rejection.
    /// </summary>
    /// <param name="request">The client management request to validate.</param>
    Task<Result<ValidClientRequest, OidcError>> ValidateAsync(ClientRequest request);
}
