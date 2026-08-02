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
