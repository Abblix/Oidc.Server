// Abblix OIDC Client Library
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

namespace Abblix.Oidc.Client.Features.AuthorizationResponses;

/// <summary>
/// What kind of answer came back from the authorization endpoint.
/// </summary>
public enum AuthorizationResponseKind
{
    /// <summary>
    /// Neither a code nor an error: nothing this client can act on.
    /// </summary>
    /// <remarks>
    /// Kept as its own case rather than folded into the error one, because it means something different
    /// to whoever has to answer for it. An error is the provider saying no, in a vocabulary defined for
    /// saying no; this is a request that reached the callback address without being an authorization
    /// response at all - a stray link, a scanner, a misconfigured route.
    /// </remarks>
    Unrecognized = 0,

    /// <summary>
    /// A successful response carrying an authorization code (RFC 6749 section 4.1.2).
    /// </summary>
    AuthorizationCode,

    /// <summary>
    /// The provider refused, and said why (RFC 6749 section 4.1.2.1).
    /// </summary>
    Error,

    /// <summary>
    /// Both a code and an error arrived, which no specification defines.
    /// </summary>
    /// <remarks>
    /// Named rather than resolved. Picking either reading invents behaviour the specifications do not
    /// describe, and the safe-looking choice is the dangerous one: treating it as an error discards a
    /// real code, while treating it as a success acts on a code the provider paired with a refusal.
    /// A response nobody wrote down the meaning of is not one to guess at.
    /// </remarks>
    Contradictory,
}

/// <summary>
/// An authorization response, taken apart but not yet judged.
/// </summary>
/// <remarks>
/// Nothing here has been verified. The values are what arrived at the callback address, and until the
/// issuer has been checked they are not even known to have come from the provider this client asked -
/// RFC 9207 section 2.4 is explicit that for error responses "clients MUST NOT assume that the error
/// originates from the intended authorization server". That is why parsing and judging are separate
/// steps: something has to hold the parameters while the checks run, and it should not look like a
/// verdict while it does.
/// </remarks>
public sealed record AuthorizationResponse
{
    /// <summary>
    /// Which of the four shapes this response has.
    /// </summary>
    public required AuthorizationResponseKind Kind { get; init; }

    /// <summary>
    /// The authorization code, when one came back.
    /// </summary>
    public string? Code { get; init; }

    /// <summary>
    /// The <c>state</c> echoed by the provider, when one came back.
    /// </summary>
    /// <remarks>
    /// Present on both a success and an error: RFC 6749 sections 4.1.2 and 4.1.2.1 both require it back
    /// when the request carried one. This client always sends one, so its absence is already a fault.
    /// </remarks>
    public string? State { get; init; }

    /// <summary>
    /// The error code, when the provider refused. One of <see cref="ErrorCodes"/>, or a value from an
    /// extension this client does not know.
    /// </summary>
    public string? Error { get; init; }

    /// <summary>
    /// The provider's human-readable elaboration on <see cref="Error"/>, when it gave one.
    /// </summary>
    /// <remarks>
    /// Text chosen by whoever sent the response, which until the issuer check passes is not certainly
    /// the provider. Treat it as untrusted: it belongs in a log entry that says where it came from, not
    /// in a page rendered to the user, and never in markup. RFC 6749 section 4.1.2.1 bounds only its
    /// character set - "Values for the 'error_description' parameter MUST NOT include characters
    /// outside the set %x20-21 / %x23-5B / %x5D-7E" - which rules out quotes and backslashes but says
    /// nothing about meaning, and a conforming value can still read as an instruction to the user.
    /// </remarks>
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// A page the provider offers about the error, when it gave one.
    /// </summary>
    /// <remarks>
    /// An address supplied by the response, so it is a redirect target in the same sense a
    /// <c>?returnUrl=</c> is: not somewhere to send a user without deciding to. Typed as a string
    /// rather than a <see cref="Uri"/> deliberately, so that nothing about it suggests navigation.
    /// </remarks>
    public string? ErrorUri { get; init; }

    /// <summary>
    /// The <c>iss</c> parameter of RFC 9207, when the provider sent one.
    /// </summary>
    public string? Issuer { get; init; }
}
