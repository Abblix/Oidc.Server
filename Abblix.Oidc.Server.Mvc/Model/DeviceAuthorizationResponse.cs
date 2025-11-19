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

using System.Text.Json.Serialization;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// Represents the response from a device authorization endpoint as defined in RFC 8628.
/// This response includes the device code, user code, and verification URIs that enable
/// the user to complete the authorization on a separate device.
/// </summary>
public record DeviceAuthorizationResponse
{
    /// <summary>
    /// The device verification code that the client will use to poll for authorization status.
    /// </summary>
    [JsonPropertyName("device_code")]
    public required string DeviceCode { get; init; }

    /// <summary>
    /// The end-user verification code that the user will enter on the verification URI.
    /// </summary>
    [JsonPropertyName("user_code")]
    public required string UserCode { get; init; }

    /// <summary>
    /// The verification URI where the user should navigate to enter the user code.
    /// </summary>
    [JsonPropertyName("verification_uri")]
    public required Uri VerificationUri { get; init; }

    /// <summary>
    /// Optional verification URI that includes the user code, allowing for a direct link.
    /// </summary>
    [JsonPropertyName("verification_uri_complete")]
    public Uri? VerificationUriComplete { get; init; }

    /// <summary>
    /// The lifetime of the device code and user code.
    /// </summary>
    [JsonPropertyName("expires_in")]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    public required TimeSpan ExpiresIn { get; init; }

    /// <summary>
    /// The minimum amount of time that the client should wait between polling requests.
    /// </summary>
    [JsonPropertyName("interval")]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    public required TimeSpan Interval { get; init; }
}
