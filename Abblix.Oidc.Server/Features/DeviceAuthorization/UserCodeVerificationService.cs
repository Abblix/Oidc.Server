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
/// <param name="httpContextAccessor">Accessor for the current HTTP context to retrieve client IP.</param>
public class UserCodeVerificationService(
    IDeviceAuthorizationStorage storage,
    IUserCodeRateLimiter rateLimiter,
    IHttpContextAccessor httpContextAccessor) : IUserCodeVerificationService
{
    /// <inheritdoc />
    public async Task<UserCodeVerificationResult> VerifyAsync(string userCode)
    {
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
        return new ValidUserCode(request.ClientId, request.Scope, request.Resources);
    }

    /// <inheritdoc />
    public async Task<bool> ApproveAsync(string userCode, AuthorizedGrant authorizedGrant)
    {
        var result = await storage.TryGetByUserCodeAsync(userCode);
        if (result == null)
            return false;

        var (deviceCode, request) = result.Value;

        if (request.Status != DeviceAuthorizationStatus.Pending)
            return false;

        request.Status = DeviceAuthorizationStatus.Authorized;
        request.AuthorizedGrant = authorizedGrant;

        await storage.UpdateAsync(deviceCode, request);
        return true;
    }

    /// <inheritdoc />
    public async Task<bool> DenyAsync(string userCode)
    {
        var result = await storage.TryGetByUserCodeAsync(userCode);
        if (result == null)
            return false;

        var (deviceCode, request) = result.Value;

        if (request.Status != DeviceAuthorizationStatus.Pending)
            return false;

        request.Status = DeviceAuthorizationStatus.Denied;

        await storage.UpdateAsync(deviceCode, request);
        return true;
    }
}
