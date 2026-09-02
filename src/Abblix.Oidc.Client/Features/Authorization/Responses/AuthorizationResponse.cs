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

using System.Text.Json.Serialization;

namespace Abblix.Oidc.Client.Features.Authorization.Responses;

/// <summary>
/// The authorization response as it arrives at the redirect address, whether by query, fragment or
/// form_post: the success parameters of whichever flow was used, or the error.
/// </summary>
/// <remarks>
/// The wire projection, bound from the delivered parameters by their names rather than read out one at a
/// time - the mirror of the server's own <c>Model.AuthorizationResponse</c>, so the same wire value has
/// the same name and type on both sides of the family.
/// Nothing here has been verified. The values are what arrived, and until the issuer has been checked
/// they are not even known to have come from the provider this client asked: RFC 9207 section 2.4 is
/// explicit that for error responses "clients MUST NOT assume that the error originates from the intended
/// authorization server". Binding and judging stay separate steps, and this type is the former - it holds
/// the parameters while the checks run, and is deliberately shaped so it cannot be mistaken for a verdict.
/// </remarks>
public sealed record AuthorizationResponse
{
    /// <summary>
    /// The authorization code, in the code and hybrid flows (RFC 6749 section 4.1.2).
    /// </summary>
    [JsonPropertyName(Parameters.Code)]
    public string? Code { get; init; }

    /// <summary>
    /// The <c>state</c> echoed by the provider.
    /// </summary>
    /// <remarks>
    /// Returned on both a success and an error: RFC 6749 sections 4.1.2 and 4.1.2.1 both require it back
    /// when the request carried one. This client always sends one, so a response without it is refused -
    /// but it is refused by a check, not by this type. Nullable is what the type honestly knows: whoever
    /// reaches the redirection address decides which parameters arrive, and a shape that cannot represent
    /// their absence could only pretend the absent case away. The refusal is
    /// <see cref="Context.AuthorizationStateFailure.Missing"/>, and it is deliberately told apart from a
    /// state this client is not holding.
    /// </remarks>
    [JsonPropertyName(Parameters.State)]
    public string? State { get; init; }

    /// <summary>
    /// An ID Token returned from the authorization endpoint, in the implicit and hybrid flows
    /// (OIDC Core 1.0 sections 3.2.2.5 and 3.3.2.5).
    /// </summary>
    /// <remarks>
    /// A signed assertion, but an unverified one: nothing here has checked its signature, its nonce, or
    /// the hashes that bind it to a code or access token beside it.
    /// </remarks>
    [JsonPropertyName(Parameters.IdToken)]
    public string? IdToken { get; init; }

    /// <summary>
    /// An access token returned from the authorization endpoint (RFC 6749 section 4.2.2).
    /// </summary>
    [JsonPropertyName(Parameters.AccessToken)]
    public string? AccessToken { get; init; }

    /// <summary>
    /// The type of <see cref="AccessToken"/>, which RFC 6749 section 4.2.2 makes REQUIRED alongside it.
    /// </summary>
    [JsonPropertyName(Parameters.TokenType)]
    public string? TokenType { get; init; }

    /// <summary>
    /// The lifetime of <see cref="AccessToken"/> in seconds, as the provider stated it.
    /// </summary>
    /// <remarks>
    /// A string rather than a number, because this record reports what arrived: a value that does not
    /// parse is a fact about the response for a later check to judge, not a reason for the binding to
    /// fail and lose the rest of the response with it.
    /// </remarks>
    [JsonPropertyName(Parameters.ExpiresIn)]
    public string? ExpiresIn { get; init; }

    /// <summary>
    /// The scope actually granted, present when it differs from the one requested
    /// (RFC 6749 section 4.2.2).
    /// </summary>
    [JsonPropertyName(Parameters.Scope)]
    public string? Scope { get; init; }

    /// <summary>
    /// The error code, when the provider refused. One of <see cref="AuthorizationErrorCodes"/>, or a value from an
    /// extension this client does not know.
    /// </summary>
    [JsonPropertyName(Parameters.Error)]
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
    [JsonPropertyName(Parameters.ErrorDescription)]
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// A page the provider offers about the error, when it gave one.
    /// </summary>
    /// <remarks>
    /// An address supplied by the response, so it is a redirect target in the same sense a
    /// <c>?returnUrl=</c> is: not somewhere to send a user without deciding to. Typed as a string
    /// rather than a <see cref="Uri"/> deliberately, so that nothing about it suggests navigation.
    /// </remarks>
    [JsonPropertyName(Parameters.ErrorUri)]
    public string? ErrorUri { get; init; }

    /// <summary>
    /// The <c>iss</c> parameter of RFC 9207, when the provider sent one.
    /// </summary>
    [JsonPropertyName(Parameters.Issuer)]
    public string? Issuer { get; init; }

    /// <summary>
    /// The <c>session_state</c> parameter of OpenID Connect Session Management 1.0, when the provider sent
    /// one.
    /// </summary>
    /// <remarks>
    /// Section 2 calls it "a JSON string that represents the End-User's login state at the OP" and adds that
    /// the "value is opaque to the RP", so it is carried and never read into.
    /// </remarks>
    [JsonPropertyName(Parameters.SessionState)]
    public string? SessionState { get; init; }

    /// <summary>
    /// Which of the shapes this response has, decided from the parameters that actually arrived.
    /// </summary>
    /// <remarks>
    /// Derived rather than stored, so it cannot disagree with the values beside it.
    /// </remarks>
    [JsonIgnore]
    public AuthorizationResponseKind Kind => (HasSuccessParameters, Error is not null) switch
    {
        (true, false) => AuthorizationResponseKind.Success,
        (false, true) => AuthorizationResponseKind.Error,

        // Both at once is named rather than resolved: reading it as an error discards real artifacts,
        // reading it as a success acts on artifacts the provider paired with a refusal, and no
        // specification says which it is.
        (true, true) => AuthorizationResponseKind.Contradictory,

        (false, false) => AuthorizationResponseKind.Unrecognized,
    };

    /// <summary>
    /// Whether any artifact of a successful response arrived - a code, an ID Token, or an access token.
    /// </summary>
    [JsonIgnore]
    public bool HasSuccessParameters => Code is not null || IdToken is not null || AccessToken is not null;
}
