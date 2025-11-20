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

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Provides configuration options for the Device Authorization Grant (RFC 8628).
/// </summary>
public record DeviceAuthorizationOptions
{
    /// <summary>
    /// The lifetime of device_code and user_code. After this duration, the codes expire
    /// and the client must start a new device authorization request.
    /// </summary>
    public required TimeSpan CodeLifetime { get; set; }

    /// <summary>
    /// The minimum interval that the client should wait between polling requests to the token endpoint.
    /// </summary>
    public required TimeSpan PollingInterval { get; set; }

    /// <summary>
    /// The length in bytes of the device code. The device code is a high-entropy string
    /// used by the client to poll the token endpoint.
    /// </summary>
    public required int DeviceCodeLength { get; set; }

    /// <summary>
    /// The length of the user code (number of characters).
    /// </summary>
    public required int UserCodeLength { get; set; }

    /// <summary>
    /// The alphabet used to generate user codes.
    /// Defaults to numeric digits "0123456789" for universal device compatibility.
    /// Can be set to letters like "BCDFGHJKLMNPQRSTVWXZ" (consonants without ambiguous characters)
    /// or alphanumeric like "BCDFGHJKLMNPQRSTVWXZ23456789".
    /// </summary>
    public string UserCodeAlphabet { get; set; } = "0123456789";

    private Uri? _verificationUri;

    /// <summary>
    /// The user-facing URI where users can enter their user code.
    /// This should be short and easy to remember as users will manually type it.
    /// MUST use HTTPS for security per RFC 8628 Section 6.1.
    /// </summary>
    public required Uri VerificationUri
    {
        get => _verificationUri!;
        set
        {
            if (!string.Equals(value.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    "The verification_uri MUST use HTTPS for security per RFC 8628 Section 6.1",
                    nameof(VerificationUri));
            }
            _verificationUri = value;
        }
    }

    /// <summary>
    /// The maximum number of failed user code verification attempts before exponential backoff is applied.
    /// Recommended by RFC 8628 Section 5.2 to prevent brute force attacks.
    /// </summary>
    public int MaxFailuresBeforeBackoff { get; set; } = 3;

    /// <summary>
    /// The maximum number of failed user code verification attempts allowed from a single IP address
    /// within a one-minute sliding window. Prevents distributed brute force attacks.
    /// </summary>
    public int MaxIpFailuresPerMinute { get; set; } = 10;

    /// <summary>
    /// The duration of the sliding window for per-IP rate limiting.
    /// Failed attempts outside this window are not counted toward the rate limit.
    /// </summary>
    public TimeSpan RateLimitSlidingWindow { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// The maximum duration for exponential backoff blocking.
    /// Prevents indefinite blocking even with many failed attempts.
    /// </summary>
    public TimeSpan MaxBackoffDuration { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// The expiration time for IP rate limit state in storage.
    /// Should be longer than RateLimitSlidingWindow to prevent premature cleanup.
    /// </summary>
    public TimeSpan IpRateLimitStateExpiration { get; set; } = TimeSpan.FromMinutes(2);
}
