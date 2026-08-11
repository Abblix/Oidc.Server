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

using Abblix.SecurityEvents.Validation;

namespace Abblix.SecurityEvents.Delivery;

/// <summary>
/// The IANA "Security Event Token Error Codes" registry's initial contents (RFC 8935
/// Section 2.4): the vocabulary a receiver reports a bad SET in. One registry serves both
/// delivery methods - the push failure response uses it directly (RFC 8935 Section 2.3) and the
/// poll protocol's per-token error reports reuse it by reference (RFC 8936 Section 2.6) - which
/// is why the class is named for delivery rather than for push alone.
/// </summary>
public static class DeliveryErrorCodes
{
    /// <summary>
    /// "The request body cannot be parsed as a SET, or the Event Payload within the SET does not
    /// conform to the event's definition" (RFC 8935 Section 2.4).
    /// </summary>
    public const string InvalidRequest = "invalid_request";

    /// <summary>
    /// "One or more keys used to encrypt or sign the SET is invalid or otherwise unacceptable to
    /// the SET Recipient" (RFC 8935 Section 2.4).
    /// </summary>
    public const string InvalidKey = "invalid_key";

    /// <summary>
    /// "The SET Issuer is invalid for the SET Recipient" (RFC 8935 Section 2.4).
    /// </summary>
    public const string InvalidIssuer = "invalid_issuer";

    /// <summary>
    /// "The SET Audience does not correspond to the SET Recipient" (RFC 8935 Section 2.4).
    /// </summary>
    public const string InvalidAudience = "invalid_audience";

    /// <summary>
    /// "The SET Recipient could not authenticate the SET Transmitter" (RFC 8935 Section 2.4).
    /// This is about the TRANSMITTER's credentials - transport authentication - not about the
    /// token, which is why no validation error maps to it: the pipeline never sees the transport.
    /// </summary>
    public const string AuthenticationFailed = "authentication_failed";

    /// <summary>
    /// "The SET Transmitter is not authorized to transmit the SET to the SET Recipient"
    /// (RFC 8935 Section 2.4). An authorization verdict, taken outside the token pipeline.
    /// </summary>
    public const string AccessDenied = "access_denied";

    /// <summary>
    /// SSF 1.0 extension to the registry (its Section 11 requests the assignment): "Indicates
    /// that a Verification event contained a 'state' claim that does not match the value
    /// expected by the Receiver" (SSF 1.0 Sections 8.1.4.1, 11). A verdict only the consumer
    /// holding the expected state can reach, which is why no validation error maps to it.
    /// </summary>
    public const string InvalidState = "invalid_state";

    /// <summary>
    /// Tells whether a receiver's verdict would still hold if the same bytes arrived again.
    /// </summary>
    /// <remarks>
    /// RFC 8935 Section 4 draws this line for the transmitter and gives both directions by example:
    /// "invalid_request" indicates a structural error "that is likely to remain when retransmitting the same SET",
    /// while others "such as 'access_denied' may be transient, for example, if the SET Transmitter refreshes
    /// expired credentials prior to retransmission". So the verdicts about the TOKEN are final, and the verdicts
    /// about the transmitter's standing with the receiver are not: credentials get refreshed and grants get fixed
    /// without the event changing at all.
    /// <para>
    /// An unrecognised code counts as final. The registry is extensible (Section 2.4), so a code from outside it
    /// says nothing about repeatability, and keeping the event would hold the head of a queue on a verdict nobody
    /// can interpret.
    /// </para>
    /// </remarks>
    /// <param name="errorCode">The "err" value the receiver answered with.</param>
    /// <returns>True when redelivery cannot change the answer.</returns>
    public static bool IsFinal(string? errorCode) => errorCode switch
    {
        AuthenticationFailed or AccessDenied => false,
        _ => true,
    };

    /// <summary>
    /// Translates a validation verdict into the registry code a delivery response carries.
    /// </summary>
    /// <remarks>
    /// The registry is coarser than the pipeline: it names what the TRANSMITTER can act on, so
    /// several distinct verdicts collapse into "invalid_request". The pipeline's own description
    /// still travels beside the code in the response body, so no precision is lost to the
    /// operator reading logs on the other side.
    /// </remarks>
    /// <param name="code">The validation verdict.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The verdict is not one this table knows - a new enum member was added without extending
    /// the mapping, and failing loudly here is what keeps the table from silently under-reporting
    /// it as some default.</exception>
    public static string FromValidationError(SecurityEventTokenErrorCode code) => code switch
    {
        SecurityEventTokenErrorCode.MalformedToken => InvalidRequest,
        SecurityEventTokenErrorCode.TokenConfusion => InvalidRequest,
        SecurityEventTokenErrorCode.MissingEvents => InvalidRequest,
        SecurityEventTokenErrorCode.IatOutOfRange => InvalidRequest,
        SecurityEventTokenErrorCode.Custom => InvalidRequest,
        SecurityEventTokenErrorCode.UnknownIssuer => InvalidIssuer,
        SecurityEventTokenErrorCode.SignatureInvalid => InvalidKey,
        SecurityEventTokenErrorCode.KeyNotFound => InvalidKey,
        SecurityEventTokenErrorCode.DecryptionFailed => InvalidKey,
        SecurityEventTokenErrorCode.AudienceMismatch => InvalidAudience,
        _ => throw new ArgumentOutOfRangeException(
            nameof(code),
            code,
            $"No delivery error code is mapped for this {nameof(SecurityEventTokenErrorCode)}."),
    };
}
