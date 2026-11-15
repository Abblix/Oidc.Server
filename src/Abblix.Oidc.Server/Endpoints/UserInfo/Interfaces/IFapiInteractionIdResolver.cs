// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;

/// <summary>
/// Decides the <c>x-fapi-interaction-id</c> a UserInfo response carries, the one place both hosts ask, so the
/// transport only writes the header it is handed.
/// </summary>
public interface IFapiInteractionIdResolver
{
    /// <summary>
    /// The value of the <c>x-fapi-interaction-id</c> response header, logged once decided, or null where the security
    /// profile in force does not require the header.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="client">The client the access token was issued to, or null where the request failed before the
    /// token named one; the tenant's default profile then decides.</param>
    /// <param name="received">The <c>x-fapi-interaction-id</c> request header as received, or null.</param>
    string? Resolve(TenantDefinition tenant, ClientInfo? client, string? received);
}
