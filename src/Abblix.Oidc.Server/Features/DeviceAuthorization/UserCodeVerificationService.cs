// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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

        // An approval landing after the code's fixed lifetime (RFC 8628 §3.2) cannot be redeemed, so treat
        // it as a no-op rather than reviving an expired code; this also keeps the refreshed cache TTL positive.
        var remaining = request.ExpiresAt - timeProvider.GetUtcNow();
        if (remaining <= TimeSpan.Zero)
            return false;

        // The requested entries were handed to the host on ValidUserCode, and whether they reach the
        // grant is its decision: only its verification page knows whether it displayed them, and a
        // library putting them there would grant what nobody may have shown. The one thing that must
        // not happen is the omission passing unremarked - it is either a refusal the host expressed by
        // other means, or the threading it forgot, and the two look identical from here.
        if (request.AuthorizationDetails is { Count: > 0 } requestedDetails
            && authorizedGrant.Context.AuthorizationDetails is not { Count: > 0 })
        {
            LogGrantedAuthorizationDetailsNotCarried(request.ClientId, requestedDetails.Count);
        }

        request.Status = DeviceAuthorizationStatus.Authorized;
        request.AuthorizedGrant = authorizedGrant;

        await storage.UpdateAsync(deviceCode, request, remaining);
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

        // A denial after the code's fixed lifetime (RFC 8628 §3.2) is moot - the code is already unusable, so
        // treat it as a no-op rather than writing a record with a non-positive cache TTL.
        var remaining = request.ExpiresAt - timeProvider.GetUtcNow();
        if (remaining <= TimeSpan.Zero)
            return false;

        request.Status = DeviceAuthorizationStatus.Denied;

        await storage.UpdateAsync(deviceCode, request, remaining);
        return true;
    }
}
