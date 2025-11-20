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

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Provides configuration options for the backchannel authentication process.
/// </summary>
public record BackChannelAuthenticationOptions
{
    /// <summary>
    /// Specifies the default expiration time for backchannel authentication requests.
    /// This value defines how long the authentication request will remain valid if no specific expiration
    /// time is requested. It is set to 5 minutes by default.
    /// </summary>
    public TimeSpan DefaultExpiry { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Specifies the maximum allowed expiration time for backchannel authentication requests.
    /// This value restricts the maximum duration an authentication request can be valid for,
    /// even if a longer expiration is requested. It is set to 30 minutes by default.
    /// </summary>
    public TimeSpan MaximumExpiry { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>
    /// Defines the polling interval used by clients to check the status of a backchannel authentication request.
    /// It is set to 5 seconds by default, ensuring that clients can frequently check for authentication updates
    /// without overwhelming the server.
    /// </summary>
    public TimeSpan PollingInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Indicates whether long polling is used for backchannel authentication status updates.
    /// When set to true, clients may use long polling techniques to wait for authentication status changes,
    /// which reduces the need for frequent polling requests.
    /// </summary>
    public bool UseLongPolling { get; set; } = false;

    /// <summary>
    /// Specifies the maximum time a long-polling request will wait for authentication status changes.
    /// This timeout balances responsiveness (shorter timeout) vs server load (longer timeout).
    /// Default is 30 seconds.
    /// </summary>
    /// <remarks>
    /// When a client polls for tokens while authentication is pending and long-polling is enabled,
    /// the server holds the connection open for up to this duration. If authentication completes
    /// during this window, the response is returned immediately. Otherwise, authorization_pending
    /// is returned after the timeout.
    /// </remarks>
    public TimeSpan LongPollingTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Specifies the length of authentication request identifiers used by the OIDC server.
    /// This value ensures that each backchannel authentication request is uniquely identified.
    /// Per CIBA specification, the auth_req_id MUST have a minimum entropy of 128 bits (16 bytes).
    /// </summary>
    /// <remarks>
    /// The minimum value is 16 bytes (128 bits) as required by OpenID Connect CIBA specification.
    /// Default is 64 bytes (512 bits) for enhanced security.
    /// </remarks>
    public int RequestIdLength
    {
        get => _requestIdLength;
        set
        {
            if (value < MinimumRequestIdLength)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(RequestIdLength),
                    value,
                    $"RequestIdLength must be at least {MinimumRequestIdLength} bytes (128 bits) to comply with OpenID Connect CIBA specification");
            }
            _requestIdLength = value;
        }
    }

    private int _requestIdLength = 64;

    /// <summary>
    /// Minimum length for authentication request identifiers as required by CIBA specification (128 bits = 16 bytes).
    /// </summary>
    public const int MinimumRequestIdLength = 16;

    /// <summary>
    /// Specifies the token delivery modes supported by the server for backchannel authentication.
    /// The CIBA specification defines three modes: poll, ping, and push.
    /// </summary>
    /// <remarks>
    /// Default is poll mode only. Additional modes (ping, push) require implementation of notification mechanisms.
    /// </remarks>
    public IEnumerable<string>? TokenDeliveryModesSupported { get; set; } = [BackchannelTokenDeliveryModes.Poll];

    /// <summary>
    /// Indicates whether the server supports the user_code parameter in backchannel authentication requests.
    /// When enabled, clients may provide a user code that must be validated during authentication.
    /// </summary>
    /// <remarks>
    /// This is an optional CIBA feature. When enabled, the UserCodeValidator will enforce user code presence
    /// for clients configured to require it.
    /// </remarks>
    public bool UserCodeParameterSupported { get; set; } = false;

    /// <summary>
    /// Specifies the lifetime for HTTP client handlers used in ping mode notifications.
    /// This controls how long HttpClient instances are pooled before being recreated.
    /// </summary>
    /// <remarks>
    /// Default is 5 minutes. Shorter lifetimes help with DNS changes and connection pool refresh,
    /// but may impact performance. Longer lifetimes reduce overhead but may cause stale connections.
    /// </remarks>
    public TimeSpan NotificationHttpClientHandlerLifetime { get; set; } = TimeSpan.FromMinutes(5);
}
