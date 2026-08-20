// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// The minimum device code length in bytes (128 bits). The device code is never displayed to
    /// the user, so it carries no usability constraint and RFC 8628 Section 5.2 requires very high
    /// entropy; 128 bits is the conventional cryptographic floor for a non-guessable random value.
    /// </summary>
    private const int MinDeviceCodeLengthBytes = 16;

    private int _deviceCodeLength;

    /// <summary>
    /// The length in bytes of the device code. The device code is a high-entropy string
    /// used by the client to poll the token endpoint. Must be at least 128 bits (16 bytes)
    /// of entropy per RFC 8628 Section 5.2.
    /// </summary>
    public required int DeviceCodeLength
    {
        get => _deviceCodeLength;
        set
        {
            if (value < MinDeviceCodeLengthBytes)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(DeviceCodeLength),
                    value,
                    $"The device_code MUST contain very high entropy per RFC 8628 Section 5.2; " +
                    $"the length must be at least {MinDeviceCodeLengthBytes} bytes (128 bits).");
            }
            _deviceCodeLength = value;
        }
    }

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
        // `required` is a compiler obligation on an object initialiser and nothing more: the configuration
        // binder does not honour it, and for an absent reference-typed member it never calls the setter at
        // all. A host binding a partial DeviceAuthorization section therefore reaches here with nothing set,
        // and handing that null onwards produced an ArgumentNullException from a URI builder on every device
        // authorization request - pointing at the plumbing rather than at the setting that was missed.
        get => _verificationUri ?? throw new InvalidOperationException(
            $"{nameof(VerificationUri)} is not configured. The device authorization endpoint cannot state "
            + "where the user should enter their code, which RFC 8628 section 3.2 makes a required member "
            + "of the response.");
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
