// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// The approved device code a grant was read from, claimed once tokens are issued for it.
/// </summary>
/// <param name="storage">Holds the device authorization the code names.</param>
/// <param name="deviceCode">The device code being redeemed.</param>
/// <param name="userCode">The user code of the authorization read, whose index the claim removes too.</param>
internal sealed class DeviceCodeRedemption(
    IDeviceAuthorizationStorage storage,
    [Credential] string deviceCode,
    [Credential] string userCode) : ISingleUseRedemption
{
    /// <inheritdoc />
    public async Task<OidcError?> SpendAsync(TenantDefinition tenant, ClientInfo clientInfo)
    {
        // Removed through the store's claim protocol, which is what keeps two polls from both being told they took
        // the authorized grant, however many processes are polling. A refusal here is not a diagnosis: a competitor
        // produces it, and so does a claim that expired mid-protocol with nobody to lose to. RFC 8628 requires no
        // such single exchange of a device code anywhere; that is this library's decision, and this is where it is
        // enforced.
        if (await storage.TryRemoveAsync(tenant, deviceCode, userCode))
            return null;

        return new OidcError(ErrorCodes.ExpiredToken, "The device code has expired or was already used");
    }
}
