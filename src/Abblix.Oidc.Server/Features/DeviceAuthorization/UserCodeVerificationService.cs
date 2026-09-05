// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Implements the user code verification service for the Device Authorization Grant flow (RFC 8628).
/// This service handles the verification, approval, and denial of device authorization requests
/// with built-in brute force protection.
/// </summary>
/// <param name="logger">Records what an approval left behind, since the library cannot supply it.</param>
/// <param name="storage">The storage service for device authorization requests.</param>
/// <param name="rateLimiter">The rate limiter for preventing brute force attacks.</param>
/// <param name="normalizer">Canonicalizes user-entered codes before lookup (RFC 8628 Section 6.1).</param>
/// <param name="requestInfoProvider">Supplies the client IP the rate limiter buckets by. The core reads it
/// through this abstraction rather than the HTTP context so it stays independent of the host, and so a test
/// can drive the limiter without standing up a web host.</param>
/// <param name="timeProvider">Provides the current time for deriving the request's remaining lifetime.</param>
public partial class UserCodeVerificationService(
    ILogger<UserCodeVerificationService> logger,
    IDeviceAuthorizationStorage storage,
    IUserCodeRateLimiter rateLimiter,
    IUserCodeNormalizer normalizer,
    IRequestInfoProvider requestInfoProvider,
    TimeProvider timeProvider) : IUserCodeVerificationService
{
    /// <inheritdoc />
    public async Task<UserCodeVerificationResult> VerifyAsync(string userCode)
    {
        // Canonicalize before both rate limiting and lookup: this accepts the readability variants
        // the user may have typed and keeps a single rate-limit bucket per logical code, so case or
        // dash variations cannot be used to multiply the per-code brute-force budget.
        userCode = normalizer.Normalize(userCode);

        var clientIp = requestInfoProvider.RemoteIpAddress?.ToString() ?? "unknown";

        // Check rate limiting before attempting verification
        var rateLimitCheck = await rateLimiter.CheckAsync(userCode, clientIp);
        if (rateLimitCheck.TryGetFailure(out _))
        {
            // Return invalid to prevent information disclosure about valid vs invalid codes
            // The rate limiter will log the security event
            return new InvalidUserCode();
        }

        var result = await storage.TryGetByUserCodeAsync(userCode);
        if (result == null)
        {
            // Record failed attempt for rate limiting
            await rateLimiter.RecordFailureAsync(userCode, clientIp);
            return new InvalidUserCode();
        }

        var (_, request) = result.Value;
        if (request.Status != DeviceAuthorizationStatus.Pending)
        {
            // Code already used - still record as failure to prevent enumeration
            await rateLimiter.RecordFailureAsync(userCode, clientIp);
            return new UserCodeAlreadyUsed();
        }

        // A code past its lifetime is as dead as a used one, and the approval that follows this step
        // refuses it without a reason - so answering valid here shows the user a consent screen for
        // nothing. It counts as a FAILURE for the same reason the used code does: success resets the
        // per-code counter, so one expired-but-pending code would otherwise clear that bucket at will
        // and its brute-force budget would never fill. InvalidUserCode is what its own contract already
        // promises for this - "not found or has expired".
        if (!request.HasLifetimeLeft(timeProvider.GetUtcNow(), out _))
        {
            await rateLimiter.RecordFailureAsync(userCode, clientIp);
            return new InvalidUserCode();
        }

        // Valid user code found and pending - record success to reset counters
        await rateLimiter.RecordSuccessAsync(userCode, clientIp);
        return new ValidUserCode(request.ClientId, request.Scope, request.Resources, request.AuthorizationDetails);
    }

    /// <inheritdoc />
    public async Task<bool> ApproveAsync(string userCode, AuthorizedGrant authorizedGrant)
    {
        userCode = normalizer.Normalize(userCode);
        var result = await storage.TryGetByUserCodeAsync(userCode);
        if (result == null)
            return false;

        var (deviceCode, request) = result.Value;

        if (request.Status != DeviceAuthorizationStatus.Pending)
            return false;

        // An approval landing after the code's fixed lifetime (RFC 8628 section 3.2) cannot be redeemed, so treat
        // it as a no-op rather than reviving an expired code; this also keeps the refreshed cache TTL positive.
        if (!request.HasLifetimeLeft(timeProvider.GetUtcNow(), out var remaining))
            return false;

        // Narrowing is the host's to decide; widening is not. A grant carrying a type the device
        // authorization request never asked for gives the device authority nobody requested, and this is
        // the last place holding both sides: the requested entries live on the record, and the grant
        // about to replace them is the one the token is built from.
        if (GrantedAuthorizationDetails.EscapedTypes(request, authorizedGrant) is { Length: > 0 } escaped)
        {
            LogGrantedAuthorizationDetailsExceedTheRequest(
                request.ClientId, string.Join(", ", escaped));

            return false;
        }

        if (!await TryDecideAsync(
                deviceCode,
                remaining,
                current =>
                {
                    current.Status = DeviceAuthorizationStatus.Authorized;
                    current.AuthorizedGrant = authorizedGrant;
                }))
        {
            return false;
        }

        // The requested entries were handed to the host on ValidUserCode, and whether they reach the
        // grant is its decision: only its verification page knows whether it displayed them, and a
        // library putting them there would grant what nobody may have shown. The one thing that must
        // not happen is the omission passing unremarked - it is either a refusal the host expressed by
        // other means, or the threading it forgot, and the two look identical from here.
        //
        // Said after the write, so the line never describes an approval that did not happen.
        if (request.AuthorizationDetails is { Count: > 0 } requestedDetails
            && authorizedGrant.Context.AuthorizationDetails is not { Count: > 0 })
        {
            LogGrantedAuthorizationDetailsNotCarried(request.ClientId, requestedDetails.Count);
        }

        return true;
    }

    /// <inheritdoc />
    public async Task<bool> DenyAsync(string userCode)
    {
        userCode = normalizer.Normalize(userCode);
        var result = await storage.TryGetByUserCodeAsync(userCode);
        if (result == null)
            return false;

        var (deviceCode, request) = result.Value;

        if (request.Status != DeviceAuthorizationStatus.Pending)
            return false;

        // A denial after the code's fixed lifetime (RFC 8628 section 3.2) is moot - the code is already unusable, so
        // treat it as a no-op rather than writing a record with a non-positive cache TTL.
        if (!request.HasLifetimeLeft(timeProvider.GetUtcNow(), out var remaining))
            return false;

        return await TryDecideAsync(
            deviceCode, remaining, current => current.Status = DeviceAuthorizationStatus.Denied);
    }

    /// <summary>
    /// Applies a decision to the record as it stands NOW, refusing when it has moved on since the user
    /// code was looked up.
    /// </summary>
    /// <remarks>
    /// Everything between the lookup and the write is a window, and a write of the record read earlier
    /// RESTORES it - so a later poll finds an authorized record for a code that was already exchanged,
    /// and a second full token set is issued for one device code. Nothing downstream catches it: the net
    /// the authorization-code path has is the reuse decorator inspecting the claimed grant, and the
    /// device path has no equivalent.
    /// <para>
    /// It takes TWO decisions, and that is the precondition the hazard is easy to state without. While
    /// the record reads Pending no poll CONSUMES it: the only arm that issues anything needs it to read
    /// Authorized first. A poll does remove a pending record once its lifetime is over, and that arm
    /// issues nothing, so it cannot produce the second token set. The sequence therefore needs another
    /// decision to move the record off Pending - which is exactly the clause a guard written only
    /// against a REMOVED record would miss.
    /// </para>
    /// <para>
    /// The same shape <c>DeviceCodeGrantHandler.TryBumpNextPollAsync</c> already uses on this store, and
    /// with the same limit: re-reading NARROWS the window to the store round trip and does not close it.
    /// Closing it needs a compare-and-swap the entity storage does not expose, which is issue 194.
    /// </para>
    /// </remarks>
    /// <param name="deviceCode">The record to decide on.</param>
    /// <param name="remaining">The lifetime left, applied as the cache TTL so the code cannot be extended.</param>
    /// <param name="decide">Applies the decision to the freshly read record.</param>
    private async Task<bool> TryDecideAsync(
        string deviceCode,
        TimeSpan remaining,
        Action<DeviceAuthorizationRequest> decide)
    {
        var current = await storage.TryGetByDeviceCodeAsync(deviceCode);
        if (current is not { Status: DeviceAuthorizationStatus.Pending })
        {
            return false;
        }

        decide(current);
        await storage.UpdateAsync(deviceCode, current, remaining);
        return true;
    }
}
