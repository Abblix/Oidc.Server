// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Implements the user code verification service for the Device Authorization Grant flow (RFC 8628).
/// This service handles the verification, approval, and denial of device authorization requests
/// with built-in brute force protection.
/// </summary>
/// <param name="storage">The storage service for device authorization requests.</param>
/// <param name="rateLimiter">The rate limiter for preventing brute force attacks.</param>
/// <param name="normalizer">Canonicalizes user-entered codes before lookup (RFC 8628 Section 6.1).</param>
/// <param name="httpContextAccessor">Accessor for the current HTTP context to retrieve client IP.</param>
/// <param name="timeProvider">Provides the current time for deriving the request's remaining lifetime.</param>
public class UserCodeVerificationService(
    IDeviceAuthorizationStorage storage,
    IUserCodeRateLimiter rateLimiter,
    IUserCodeNormalizer normalizer,
    IHttpContextAccessor httpContextAccessor,
    TimeProvider timeProvider) : IUserCodeVerificationService
{
    /// <inheritdoc />
    public async Task<UserCodeVerificationResult> VerifyAsync(string userCode)
    {
        // Canonicalize before both rate limiting and lookup: this accepts the readability variants
        // the user may have typed and keeps a single rate-limit bucket per logical code, so case or
        // dash variations cannot be used to multiply the per-code brute-force budget.
        userCode = normalizer.Normalize(userCode);

        var clientIp = httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";

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
