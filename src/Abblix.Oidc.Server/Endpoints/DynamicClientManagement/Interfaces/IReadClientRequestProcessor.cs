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
/// Builds the RFC 7592 §2.1 read-client response from a request that has already been validated.
/// Reads stored metadata, formats it for the wire, and issues a fresh
/// <c>registration_access_token</c> as recommended by RFC 7592 §3.
/// </summary>
public interface IReadClientRequestProcessor
{
    /// <summary>
    /// Produces the response payload for the addressed client, including its current metadata
    /// and a refreshed registration access token.
    /// </summary>
    /// <param name="request">A request whose authentication and target client have been validated.</param>
    Task<Result<ReadClientSuccessfulResponse, OidcError>> ProcessAsync(ValidClientRequest request);
}
