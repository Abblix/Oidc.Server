// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents a successful device authorization response as defined in RFC 8628.
/// This response contains the device code the client uses to poll the token endpoint
/// and the user code the device displays to the user for entry on a separate device.
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
    /// The end-user verification URI where the user enters the user code (RFC 8628 section 3.2). Carried on the wire DTO and
    /// filled by the transport layer from the configured device authorization options; the protocol processor leaves
    /// it unset.
    /// </summary>
    [JsonPropertyName(Parameters.VerificationUri)]
    public Uri? VerificationUri { get; init; }

    /// <summary>
    /// The optional verification URI that already embeds the user code (RFC 8628 section 3.2), letting capable devices render
    /// a direct link or QR code so the user skips typing the code. Filled by the transport layer.
    /// </summary>
    [JsonPropertyName(Parameters.VerificationUriComplete)]
    public Uri? VerificationUriComplete { get; init; }

    /// <summary>
    /// The lifetime of the <c>device_code</c> and <c>user_code</c>.
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
        /// <summary>The <c>device_code</c> response parameter the device polls the token endpoint with
        /// (RFC 8628 section 3.2).</summary>
        public const string DeviceCode = "device_code";

        /// <summary>The <c>user_code</c> response parameter displayed to the end-user for entry on the
        /// verification page (RFC 8628 section 3.2).</summary>
        public const string UserCode = "user_code";

        /// <summary>The <c>verification_uri</c> response parameter the end-user navigates to in order to enter the
        /// user code (RFC 8628 section 3.2).</summary>
        public const string VerificationUri = "verification_uri";

        /// <summary>The <c>verification_uri_complete</c> response parameter that embeds the user code in the
        /// verification URI (RFC 8628 section 3.2).</summary>
        public const string VerificationUriComplete = "verification_uri_complete";

        /// <summary>The <c>expires_in</c> response parameter giving the lifetime of <c>device_code</c>
        /// and <c>user_code</c> in seconds.</summary>
        public const string ExpiresIn = "expires_in";

        /// <summary>The <c>interval</c> response parameter giving the minimum polling interval the device
        /// should observe, in seconds.</summary>
        public const string Interval = "interval";
    }
}
