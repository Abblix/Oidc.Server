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
/// Performs the storage-level deregistration of a client whose request has already been
/// validated for authentication and existence per RFC 7592 §2.3.
/// </summary>
public interface IRemoveClientRequestProcessor
{
    /// <summary>
    /// Removes the addressed client from the data store and records the removal timestamp.
    /// </summary>
    /// <param name="request">A request whose authentication and target client have been validated.</param>
    Task<Result<RemoveClientSuccessfulResponse, OidcError>> ProcessAsync(ValidClientRequest request);
}
