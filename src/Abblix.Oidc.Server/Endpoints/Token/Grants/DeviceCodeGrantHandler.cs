// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Handles the Device Code grant type as defined in RFC 8628.
/// This handler validates token requests for the device authorization flow,
/// checking the device code status and returning tokens when authorized.
/// </summary>
/// <param name="logger">Records a refusal the client learns nothing from, and the approval path cannot
/// have reported.</param>
/// <param name="storage">Service for storing and retrieving device authorization requests.</param>
/// <param name="authorizationDetailsPolicy">Asks the per-type validators whether the grant's
/// authorization_details are still acceptable, which is the only comparison that can see inside an
/// entry.</param>
/// <param name="timeProvider">Provides access to the current time.</param>
/// <param name="options">Configuration options containing polling interval settings.</param>
public partial class DeviceCodeGrantHandler(
    ILogger<DeviceCodeGrantHandler> logger,
    IDeviceAuthorizationStorage storage,
    IAuthorizationDetailsPolicy authorizationDetailsPolicy,
    TimeProvider timeProvider,
    IOptions<OidcOptions> options) : IAuthorizationGrantHandler
{
    /// <inheritdoc />
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.DeviceAuthorization; }
    }

    /// <inheritdoc />
    public async Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(
        TokenRequest request,
        ClientInfo clientInfo,
    CancellationToken cancellationToken)
    {
        // RFC 6749 §5.2: a missing required parameter is the caller's protocol error (invalid_request),
        // not a server fault - the previous throw-on-access surfaced it as HTTP 500.
        if (!request.DeviceCode.HasValue())
        {
            return ErrorFactory.MissingParameter(TokenRequest.Parameters.DeviceCode);
        }

        var deviceRequest = await storage.TryGetByDeviceCodeAsync(request.DeviceCode);

        var deviceAuthOptions = options.Value.DeviceAuthorization
            .NotNull(nameof(OidcOptions.DeviceAuthorization));
        var pollingInterval = deviceAuthOptions.PollingInterval;

        // A single clock read shared by the expiry gate and the remaining-lifetime passed to UpdateAsync, so
        // the two never disagree and the refreshed cache TTL is guaranteed positive (RFC 8628 §3.2).
        var now = timeProvider.GetUtcNow();

        switch (deviceRequest)
        {
            // Device code not found or expired
            case null:
                return new OidcError(ErrorCodes.ExpiredToken, "The device code has expired");

            // Device code belongs to different client
            case { ClientId: var clientId } when clientId != clientInfo.ClientId:
                return new OidcError(ErrorCodes.InvalidGrant, "The device code was issued to another client");

            // Code has reached its fixed RFC 8628 §3.2 lifetime - reject and clean up rather than letting a
            // polling client keep it alive by resetting the cache TTL
            case { } when now >= deviceRequest.ExpiresAt:
                await storage.RemoveAsync(request.DeviceCode);
                return new OidcError(ErrorCodes.ExpiredToken, "The device code has expired");

            // User has authorized the device - atomically claim the authorization
            case { Status: DeviceAuthorizationStatus.Authorized }
                when !await storage.TryRemoveAsync(request.DeviceCode, deviceRequest.UserCode):

                // Atomic get-and-remove, so two concurrent polls cannot both retrieve the authorized
                // grant and both be issued tokens. RFC 8628 states no such rule anywhere - exchanging a
                // device code once is this library's decision, and this arm is where it is enforced.

                return new OidcError(
                    ErrorCodes.ExpiredToken,
                    "The device code has expired or was already used");

            // User has authorized the device - return the authorized grant
            case { Status: DeviceAuthorizationStatus.Authorized, AuthorizedGrant: { } authorizedGrant }:

                // Judged again, on what is actually being redeemed. IUserCodeVerificationService refuses a
                // widened grant when the end user approves, but the host owns the same storage and can
                // write to it afterwards - a retried or corrected approval is the ordinary shape of that,
                // not an attack. CIBA judges at both ends for the same reason.
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

                    return new OidcError(
                        ErrorCodes.AccessDenied,
                        "The grant carries authorization_details the device authorization request "
                        + "did not ask for");
                }

                // And what the type comparison above structurally cannot see: an entry of a type the
                // request DID ask for, carrying content it did not - a raised amount, a widened set of
                // accounts. RFC 9396 §6.1 leaves that to the type's own validator, so this asks it.
                // On a copy: the question must not rewrite its own subject.
                if (await authorizationDetailsPolicy.RefuseAsync(
                        authorizedGrant, clientInfo, cancellationToken) is { } refusal)
                {
                    // The reason goes to the log and a fixed string to the client, matching the gate
                    // above: a granted-phase rejection names a host-side defect, and its text is
                    // written for whoever fixes it.
                    LogGrantedAuthorizationDetailsRefused(clientInfo.ClientId, refusal.Reason);
                    return refusal.Error;
                }

                return authorizedGrant;

            // Authorized, and nothing to issue from. Reached only when the grant is missing, because the
            // arm above binds it - and nothing in this library writes such a record: approval sets the
            // grant beside the status. Both members are public and settable on a record any host can read
            // back through the public storage interface, so writing the two apart takes one line.
            //
            // What it used to reach was the default arm, which threw naming the STATUS: "Unexpected device
            // authorization status: Authorized", about a status this switch plainly handles. The client
            // got HTTP 500 and an operator got a sentence pointing at a state machine that is not the
            // problem.
            //
            // The code is already claimed by the arm two above, which removes it before anything is
            // judged, so the record is gone by the time this is reached: a retry answers expired_token and
            // nobody can look at what was stored. That makes this log line the only account of it, which
            // is why it names the missing member rather than the status, and why it sits at Error.
            //
            // Refusing WITHOUT consuming the code, so the record survives for an operator to inspect, is
            // the real alternative. It is declined because single use is enforced one arm above, and an
            // exception here would be a second, quieter rule about when a device code survives
            // redemption, triggered by which member of the record happened to be missing.
            //
            // invalid_grant rather than one of the device-specific codes: section 3.5 admits the errors of
            // RFC 6749 section 5.2 alongside its own four, and this is a grant that cannot be used rather
            // than one the end user denied or one that ran out of time.
            case { Status: DeviceAuthorizationStatus.Authorized }:

                LogAuthorizedRecordCarriesNoGrant(clientInfo.ClientId);

                return new OidcError(
                    ErrorCodes.InvalidGrant,
                    "The device authorization cannot be redeemed");

            // Authorization still pending - check polling rate
            case { Status: DeviceAuthorizationStatus.Pending, NextPollAt: { } nextPollAt }
                when now < nextPollAt:

                // Polling too fast - increase the interval per RFC 8628 Section 3.5. Persisting the stale
                // Pending snapshot here would revert an approval that landed after the read above, so the
                // helper re-reads and this re-dispatches when the status has advanced under us.
                if (!await TryBumpNextPollAsync(
                        request.DeviceCode, nextPollAt + pollingInterval, deviceRequest.ExpiresAt - now))
                {
                    return await AuthorizeAsync(request, clientInfo, cancellationToken);
                }

                return new OidcError(
                    ErrorCodes.SlowDown,
                    "Polling too frequently. Increase the interval between requests.");

            // Authorization still pending - update next poll time
            case { Status: DeviceAuthorizationStatus.Pending }:

                if (!await TryBumpNextPollAsync(
                        request.DeviceCode, now + pollingInterval, deviceRequest.ExpiresAt - now))
                {
                    return await AuthorizeAsync(request, clientInfo, cancellationToken);
                }

                return new OidcError(
                    ErrorCodes.AuthorizationPending,
                    "The authorization request is still pending. The user has not yet completed authorization.");

            // User denied the request
            case { Status: DeviceAuthorizationStatus.Denied }:
                await storage.RemoveAsync(request.DeviceCode);
                return new OidcError(
                    ErrorCodes.AccessDenied,
                    "The user denied the authorization request.");

            default:
                throw new InvalidOperationException(
                    $"Unexpected device authorization status: {deviceRequest.Status}");
        }
    }

    // Re-reads the record and only writes the rate-limit bump when it is still Pending, so a concurrent
    // approval is not overwritten. Returns false when the status has advanced, signalling the caller to
    // re-dispatch on the fresh state. The remaining lifetime is computed by the caller from the same clock
    // read as the expiry gate, so the refreshed cache TTL stays positive and cannot extend the code
    private async Task<bool> TryBumpNextPollAsync(string deviceCode, DateTimeOffset nextPollAt, TimeSpan remaining)
    {
        var current = await storage.TryGetByDeviceCodeAsync(deviceCode);
        if (current is not { Status: DeviceAuthorizationStatus.Pending })
        {
            return false;
        }

        current.NextPollAt = nextPollAt;
        await storage.UpdateAsync(deviceCode, current, remaining);
        return true;
    }
}
