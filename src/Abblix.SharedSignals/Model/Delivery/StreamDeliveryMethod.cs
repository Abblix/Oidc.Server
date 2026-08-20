// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
