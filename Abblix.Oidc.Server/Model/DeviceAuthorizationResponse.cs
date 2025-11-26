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

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents a successful device authorization response as defined in RFC 8628.
/// This response contains the device code and user code that the device displays
/// to the user for authentication on a separate device.
/// </summary>
public record DeviceAuthorizationResponse
{
    /// <summary>
    /// The device verification code used by the client to poll the token endpoint.
    /// This is a high-entropy string that uniquely identifies the authorization request.
    /// </summary>
    [JsonPropertyName(Parameters.DeviceCode)]
    public required string DeviceCode { get; init; }

    /// <summary>
    /// The end-user verification code displayed to the user.
    /// This is a short, user-friendly code that the user enters on the verification page.
    /// </summary>
    [JsonPropertyName(Parameters.UserCode)]
    public required string UserCode { get; init; }

    /// <summary>
    /// The lifetime of the device_code and user_code.
    /// After this duration, the codes expire and the client must start a new request.
    /// </summary>
    [JsonPropertyName(Parameters.ExpiresIn)]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    public TimeSpan ExpiresIn { get; init; }

    /// <summary>
    /// The minimum interval (in seconds) that the client should wait between
    /// polling requests to the token endpoint.
    /// </summary>
    [JsonPropertyName(Parameters.Interval)]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public TimeSpan Interval { get; init; }

    /// <summary>
    /// Contains constants representing the parameter names used in the device authorization response.
    /// </summary>
    public static class Parameters
    {
        public const string DeviceCode = "device_code";
        public const string UserCode = "user_code";
        public const string ExpiresIn = "expires_in";
        public const string Interval = "interval";
    }
}
