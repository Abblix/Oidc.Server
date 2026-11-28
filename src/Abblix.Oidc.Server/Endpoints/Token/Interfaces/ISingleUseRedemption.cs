// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// What a grant is redeemed with only once - a JWT Bearer assertion, a device code, a backchannel authentication
/// request - spent by <see cref="SingleUseRedemptionDecorator"/> once the token request has been answered with tokens.
/// </summary>
/// <remarks>
/// Spent after everything that can refuse the request, the token processor's own refusals included, so a request its
/// client can correct leaves the credential for the corrected one. Issuing tokens writes nothing, so of requests
/// presenting one credential at once the ones losing the spend hand over nothing they minted.
/// </remarks>
internal interface ISingleUseRedemption
{
    /// <summary>
    /// Spends the credential, refusing the request when another one has spent it.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="clientInfo">The client redeeming the grant.</param>
    /// <returns>The refusal of a credential already spent, or <c>null</c> once this request has spent it.</returns>
    Task<OidcError?> SpendAsync(TenantDefinition tenant, ClientInfo clientInfo);
}
