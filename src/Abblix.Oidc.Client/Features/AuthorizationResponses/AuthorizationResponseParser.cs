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
/// Turns the parameters that arrived at the callback address into an
/// <see cref="AuthorizationResponse"/>.
/// </summary>
public interface IAuthorizationResponseParser
{
    /// <summary>
    /// Reads the response parameters, or throws <see cref="AuthorizationResponseException"/> when they
    /// cannot be read as a response at all.
    /// </summary>
    /// <param name="parameters">
    /// The parameters as delivered, each name mapped to every value that arrived under it.
    /// </param>
    /// <remarks>
    /// The shape is a name-to-values map rather than a name-to-value one so that a repeated parameter
    /// reaches this method instead of being silently resolved by whoever collected them. Which value a
    /// collection API keeps for a duplicate - first, last, or joined - is an implementation detail of
    /// that API, and letting it decide would mean a token endpoint sees one <c>code</c> while the
    /// checks ran against another.
    /// It is also what keeps this package free of ASP.NET Core: an adapter can build the map from a
    /// query string, from a posted form, or from parameters a script lifted out of a fragment, and this
    /// method neither knows nor cares which.
    /// </remarks>
    AuthorizationResponse Parse(IReadOnlyDictionary<string, IReadOnlyList<string>> parameters);
}

/// <summary>
/// Reads an authorization response without judging it.
/// </summary>
internal sealed class AuthorizationResponseParser : IAuthorizationResponseParser
{
    public AuthorizationResponse Parse(IReadOnlyDictionary<string, IReadOnlyList<string>> parameters)
    {
        var code = Single(parameters, Parameters.Code);
        var error = Single(parameters, Parameters.Error);

        return new AuthorizationResponse
        {
            Kind = KindOf(code, error),
            Code = code,
            State = Single(parameters, Parameters.State),
            Error = error,
            ErrorDescription = Single(parameters, Parameters.ErrorDescription),
            ErrorUri = Single(parameters, Parameters.ErrorUri),
            Issuer = Single(parameters, Parameters.Issuer),
        };
    }

    /// <summary>
    /// Classifies the response by which of the two mutually exclusive parameters arrived.
    /// </summary>
    /// <remarks>
    /// RFC 6749 section 4.1.2 defines the success shape around <c>code</c> and section 4.1.2.1 the
    /// failure shape around <c>error</c>, and describes no response carrying both or neither. Rather
    /// than pick a reading for those, they are named and handed on - see
    /// <see cref="AuthorizationResponseKind"/> for why guessing is worse than refusing.
    /// </remarks>
    private static AuthorizationResponseKind KindOf(string? code, string? error) => (code, error) switch
    {
        (not null, null) => AuthorizationResponseKind.AuthorizationCode,
        (null, not null) => AuthorizationResponseKind.Error,
        (not null, not null) => AuthorizationResponseKind.Contradictory,
        (null, null) => AuthorizationResponseKind.Unrecognized,
    };

    /// <summary>
    /// Returns the one value that arrived under <paramref name="name"/>, or <see langword="null"/> when
    /// none did, and refuses a name that arrived more than once.
    /// </summary>
    /// <remarks>
    /// RFC 6749 section 3.1 forbids the repetition outright, in a sentence that covers this direction
    /// too: "Request and response parameters MUST NOT be included more than once." Refusing rather than
    /// choosing matters because the choice is exactly what an attacker would be making: a callback
    /// carrying two codes lets whichever of them a later reader picks differ from the one these checks
    /// were run against.
    /// Note what is deliberately NOT done here - an unknown parameter is left alone. Section 4.1.2 asks
    /// for that in as many words: "The client MUST ignore unrecognized response parameters." Extensions
    /// add parameters, and a client that fails on the ones it does not know breaks against a provider
    /// that has done nothing wrong.
    /// </remarks>
    private static string? Single(
        IReadOnlyDictionary<string, IReadOnlyList<string>> parameters, string name)
    {
        if (!parameters.TryGetValue(name, out var values) || values.Count == 0)
            return null;

        if (values.Count > 1)
        {
            throw new AuthorizationResponseException(
                $"The authorization response carries the '{name}' parameter {values.Count} times, and "
                + "RFC 6749 section 3.1 allows it once. Which of them is meant cannot be guessed at.");
        }

        return values[0];
    }
}
