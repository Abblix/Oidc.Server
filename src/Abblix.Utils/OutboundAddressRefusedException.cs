// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils;

/// <summary>
/// The refusal of an outbound request by <see cref="AddressValidatingHttpMessageHandler"/>: the address it names, or
/// an address its host resolves to, may not be reached.
/// </summary>
/// <remarks>
/// A type of its own so a caller tells a refusal from a failure to reach a permitted address by what was thrown
/// rather than by its wording. An <see cref="HttpRequestException"/> still, so a caller treating every transport
/// failure alike keeps doing so. Thrown where the connection is made, it arrives as the inner exception of the one
/// the transport throws.
/// </remarks>
public class OutboundAddressRefusedException : HttpRequestException
{
    /// <summary>
    /// Creates the refusal with the reason it is refused.
    /// </summary>
    /// <param name="message">Why the request may not be sent, in a form fit for a log.</param>
    public OutboundAddressRefusedException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Creates the refusal with the reason it is refused and the failure that caused it.
    /// </summary>
    /// <param name="message">Why the request may not be sent, in a form fit for a log.</param>
    /// <param name="innerException">The failure behind the refusal, such as a name that could not be resolved.</param>
    public OutboundAddressRefusedException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }

    /// <summary>
    /// Whether <paramref name="exception"/> is such a refusal, thrown directly or wrapped by the transport.
    /// </summary>
    /// <param name="exception">What a send through the handler threw.</param>
    public static bool IsRefusal(Exception exception)
        => exception is OutboundAddressRefusedException ||
           exception.InnerException is OutboundAddressRefusedException;
}
