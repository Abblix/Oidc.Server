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
/// Represents an interface for validating update client requests in the context of OpenID Connect per RFC 7592.
/// </summary>
public interface IUpdateClientRequestValidator
{
    /// <summary>
    /// Validates an update client request asynchronously.
    /// </summary>
    /// <param name="request">The update client request to validate.</param>
    /// <returns>A task representing the validation result.</returns>
    Task<Result<ValidUpdateClientRequest, OidcError>> ValidateAsync(UpdateClientRequest request);
}
