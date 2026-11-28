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
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Redeems an approved device authorization: judges the grant it carries against what the device authorization
/// request asked for, and hands it on with the device code to claim once tokens are issued for it.
/// </summary>
/// <param name="logger">Records a refusal the client learns nothing from.</param>
/// <param name="storage">Holds the device authorization the code names.</param>
/// <param name="authorizationDetailsPolicy">Asks the per-type validators whether the grant's authorization_details
/// are still acceptable.</param>
internal sealed partial class DeviceGrantRedeemer(
    ILogger logger,
    IDeviceAuthorizationStorage storage,
    IAuthorizationDetailsPolicy authorizationDetailsPolicy)
{
    /// <summary>
    /// The grant <paramref name="deviceRequest"/> was approved with, or the refusal of it.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="deviceCode">The device code being redeemed.</param>
    /// <param name="clientInfo">The client redeeming it.</param>
    /// <param name="deviceRequest">The approved device authorization, as read for this poll.</param>
    /// <param name="authorizedGrant">The grant it was approved with.</param>
    /// <param name="cancellationToken">Abandons the judgement when the caller stops waiting.</param>
    public async Task<Result<AuthorizedGrant, OidcError>> RedeemAsync(
        TenantDefinition tenant,
        [Credential] string deviceCode,
        ClientInfo clientInfo,
        DeviceAuthorizationRequest deviceRequest,
        AuthorizedGrant authorizedGrant,
        CancellationToken cancellationToken)
    {
        // Judged again, on what is actually being redeemed. IUserCodeVerificationService refuses a
        // widened grant when the end user approves, but a host writes to that same storage through
        // the public seam and can do so afterwards - a retried or corrected approval is the ordinary
        // shape of that, not an attack. CIBA judges at both ends for the same reason.
        //
        // What this catches is a host that FORGOT, not one that lies: the baseline it compares
        // against lives in the same host-owned record, so anything able to widen the grant can
        // widen the baseline in the same write. Worth having anyway, because forgetting is what
        // actually happens, and the record still carries what the client asked for, so the
        // comparison costs no new state.
        //
        // The same computation as at approval, deliberately: a second, slightly different test here
        // would disagree with the first on exactly the inputs nobody wrote a test for.
        if (GrantedAuthorizationDetails.EscapedTypes(deviceRequest, authorizedGrant) is
            { Length: > 0 } escaped)
        {
            LogGrantedAuthorizationDetailsExceedTheRequest(
                clientInfo.ClientId, string.Join(", ", escaped));

            // access_denied ends the flow (RFC 8628 section 3.5), so the record goes as a denied one does
            await storage.RemoveAsync(tenant, deviceCode);
            return new OidcError(
                ErrorCodes.AccessDenied,
                "The grant carries authorization_details the device authorization request "
                + "did not ask for");
        }

        // And what the type comparison above structurally cannot see: an entry of a type the
        // request DID ask for, carrying content it did not - a raised amount, a widened set of
        // accounts. RFC 9396 section 6.1 leaves that to the type's own validator, so this asks it.
        // On a copy: the question must not rewrite its own subject.
        if (await authorizationDetailsPolicy.RefuseAsync(
                tenant,
                authorizedGrant,
                deviceRequest.AuthorizationDetails,
                clientInfo,
                cancellationToken) is { } refusal)
        {
            // The reason goes to the log and a fixed string to the client, matching the gate
            // above: a granted-phase rejection's text is written for whoever runs the host, not
            // for the client.
            LogGrantedAuthorizationDetailsRefused(clientInfo.ClientId, refusal.Reason);
            await storage.RemoveAsync(tenant, deviceCode);
            return refusal.Error;
        }

        // The device code is claimed once tokens are issued, so a refusal its client can correct - a
        // resource outside the grant - leaves it for the corrected poll.
        return authorizedGrant with
        {
            Redemption = new DeviceCodeRedemption(storage, deviceCode, deviceRequest.UserCode),
        };
    }
}
