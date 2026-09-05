// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.Delivery;

/// <summary>
/// How a receiver tells a transmitter that a SET was bad: the body of a push failure response
/// (RFC 8935 Section 2.3) and the per-token value of a poll request's "setErrs" member
/// (RFC 8936 Section 2.2), which share this shape by the latter's reference to the former.
/// </summary>
/// <param name="Error">A code from the IANA registry, listed on <see cref="DeliveryErrorCodes"/>.</param>
/// <param name="Description">
/// A human-readable account of what failed - the half an operator on the transmitting side reads,
/// since the code alone says only which class of thing went wrong.</param>
public record DeliveryError(
    [property: JsonPropertyName(DeliveryError.ParameterNames.Error)] string Error,
    [property: JsonPropertyName(DeliveryError.ParameterNames.Description)] string Description)
{
    /// <summary>
    /// The wire names of the error members (RFC 8935 Section 2.3).
    /// </summary>
    public static class ParameterNames
    {
        /// <summary>
        /// The Security Event Token Error Code member.
        /// </summary>
        public const string Error = "err";

        /// <summary>
        /// The human-readable description member.
        /// </summary>
        public const string Description = "description";
    }
}
