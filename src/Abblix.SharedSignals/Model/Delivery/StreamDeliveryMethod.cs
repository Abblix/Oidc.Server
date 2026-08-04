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

namespace Abblix.SharedSignals.Model.Delivery;

/// <summary>
/// The delivery half of a stream's configuration: how Security Event Tokens travel from the
/// transmitter to the receiver. Each method is identified by the URI in the "method" member
/// (SSF 1.0 Section 6.1), and the polymorphic serialization dispatches on that member.
/// </summary>
[JsonConverter(typeof(StreamDeliveryMethodJsonConverter))]
public abstract class StreamDeliveryMethod
{
    /// <summary>
    /// Creates the base with the fixed delivery method URI; each subclass passes its own
    /// specification-registered value.
    /// </summary>
    /// <param name="method">The delivery method URI identifying the concrete method.</param>
    protected StreamDeliveryMethod(string method)
    {
        Method = !string.IsNullOrEmpty(method)
            ? method
            : throw new ArgumentException("A delivery method URI is required.", nameof(method));
    }

    /// <summary>
    /// The wire names of the members shared by every delivery method.
    /// </summary>
    public static class ParameterNames
    {
        /// <summary>
        /// The delivery method discriminator (SSF 1.0 Section 6.1).
        /// </summary>
        public const string Method = "method";

        /// <summary>
        /// The URL events travel through; who supplies it depends on the method - the receiver
        /// for push (SSF 1.0 Section 6.1.1), the transmitter for poll (Section 6.1.2).
        /// </summary>
        public const string EndpointUrl = "endpoint_url";
    }

    /// <summary>
    /// The URI identifying the delivery method (SSF 1.0 Section 6.1).
    /// </summary>
    [JsonPropertyName(ParameterNames.Method)]
    public string Method { get; }
}
