// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Represents an interface for processing update client requests in the context of OpenID Connect per RFC 7592.
/// </summary>
public interface IUpdateClientRequestProcessor
{
    /// <summary>
    /// Processes an update client request asynchronously and returns the updated client configuration.
    /// </summary>
    /// <param name="request">The valid update client request to process.</param>
    /// <returns>A task representing the processing result with updated client metadata.</returns>
    Task<Result<ReadClientSuccessfulResponse, OidcError>> ProcessAsync(ValidUpdateClientRequest request);
}
