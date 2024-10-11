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
    /// Specifies the length of authentication request identifiers used by the OIDC server.
    /// This value ensures that each backchannel authentication request is uniquely identified.
    /// </summary>
    public int RequestIdLength { get; set; } = 64;

    public IEnumerable<string>? TokenDeliveryModesSupported { get; set; } = new[] { BackchannelTokenDeliveryModes.Poll };

    public bool UserCodeParameterSupported { get; set; } = false;
}
