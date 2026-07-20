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

using Abblix.Oidc.Client.Features.AuthorizationResponses;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.UnitTests.Features.AuthorizationResponses;

/// <summary>
/// Reading an authorization response, before anything about it is judged.
/// </summary>
public class AuthorizationResponseParserTests
{
    private static readonly IAuthorizationResponseParser Parser = new ServiceCollection()
        .AddAuthorizationResponseParsing()
        .BuildServiceProvider()
        .GetRequiredService<IAuthorizationResponseParser>();

    private static AuthorizationResponse Parse(params (string Name, string Value)[] parameters)
        => Parser.Parse(parameters.ToDictionary(
            parameter => parameter.Name,
            parameter => (IReadOnlyList<string>)[parameter.Value],
            StringComparer.Ordinal));

    /// <summary>
    /// The success shape of RFC 6749 section 4.1.2: a code, and the state echoed back.
    /// </summary>
    [Fact]
    public void CodeAndState_ReadAsASuccess()
    {
        var response = Parse((Parameters.Code, "the-code"), (Parameters.State, "the-state"));

        Assert.Equal(AuthorizationResponseKind.AuthorizationCode, response.Kind);
        Assert.Equal("the-code", response.Code);
        Assert.Equal("the-state", response.State);
        Assert.Null(response.Error);
    }

    /// <summary>
    /// The failure shape of RFC 6749 section 4.1.2.1, which carries state as well.
    /// </summary>
    [Fact]
    public void ErrorAndState_ReadAsAnError()
    {
        var response = Parse(
            (Parameters.Error, ErrorCodes.AccessDenied),
            (Parameters.ErrorDescription, "The user said no"),
            (Parameters.State, "the-state"));

        Assert.Equal(AuthorizationResponseKind.Error, response.Kind);
        Assert.Equal(ErrorCodes.AccessDenied, response.Error);
        Assert.Equal("The user said no", response.ErrorDescription);
        Assert.Equal("the-state", response.State);
    }

    /// <summary>
    /// An unfamiliar error code survives verbatim. The registry is open - RFC 9396 adds one at this
    /// endpoint - and a code nobody recognises is the one an operator most needs to read.
    /// </summary>
    [Fact]
    public void UnknownErrorCode_IsCarriedThroughUnchanged()
    {
        var response = Parse((Parameters.Error, "invalid_authorization_details"));

        Assert.Equal(AuthorizationResponseKind.Error, response.Kind);
        Assert.Equal("invalid_authorization_details", response.Error);
    }

    /// <summary>
    /// The RFC 9207 issuer is read like any other parameter here; whether it is right is not this
    /// class's question.
    /// </summary>
    [Fact]
    public void Issuer_IsRead()
    {
        var response = Parse((Parameters.Code, "the-code"), (Parameters.Issuer, "https://auth.example.com"));

        Assert.Equal("https://auth.example.com", response.Issuer);
    }

    /// <summary>
    /// Neither a code nor an error is not an error response - it is a request that reached the callback
    /// address without being an authorization response at all.
    /// </summary>
    [Fact]
    public void NeitherCodeNorError_IsUnrecognized()
        => Assert.Equal(AuthorizationResponseKind.Unrecognized, Parse((Parameters.State, "the-state")).Kind);

    [Fact]
    public void NoParametersAtAll_IsUnrecognized()
        => Assert.Equal(
            AuthorizationResponseKind.Unrecognized,
            Parser.Parse(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)).Kind);

    /// <summary>
    /// Both at once is named rather than resolved. Reading it as an error would discard a real code;
    /// reading it as a success would act on a code the provider paired with a refusal.
    /// </summary>
    [Fact]
    public void BothCodeAndError_IsContradictory()
        => Assert.Equal(
            AuthorizationResponseKind.Contradictory,
            Parse((Parameters.Code, "the-code"), (Parameters.Error, ErrorCodes.AccessDenied)).Kind);

    /// <summary>
    /// RFC 6749 section 3.1: "Request and response parameters MUST NOT be included more than once."
    /// </summary>
    /// <remarks>
    /// Refused rather than resolved, because resolving it is the attacker's move: whichever value a
    /// later reader picks could differ from the one the checks ran against. Which value a collection API
    /// keeps for a duplicate is its own business, and that is exactly why the decision cannot be left
    /// to whoever collected the parameters.
    /// </remarks>
    [Theory]
    [InlineData(Parameters.Code)]
    [InlineData(Parameters.State)]
    [InlineData(Parameters.Error)]
    [InlineData(Parameters.Issuer)]
    public void ARepeatedParameter_IsRefused(string name)
    {
        var parameters = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            [name] = ["first", "second"],
        };

        Assert.Throws<AuthorizationResponseException>(() => Parser.Parse(parameters));
    }

    /// <summary>
    /// RFC 6749 section 4.1.2: "The client MUST ignore unrecognized response parameters." An extension
    /// adding one must not break a client that has never heard of it.
    /// </summary>
    [Fact]
    public void UnrecognizedParameters_AreIgnored()
    {
        var response = Parse(
            (Parameters.Code, "the-code"),
            ("some_extension_parameter", "whatever"),
            ("session_state", "abc"));

        Assert.Equal(AuthorizationResponseKind.AuthorizationCode, response.Kind);
        Assert.Equal("the-code", response.Code);
    }

    /// <summary>
    /// A parameter present with no value at all reads as absent rather than as an empty answer.
    /// </summary>
    [Fact]
    public void AParameterWithNoValues_ReadsAsAbsent()
    {
        var parameters = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            [Parameters.Code] = ["the-code"],
            [Parameters.State] = [],
        };

        Assert.Null(Parser.Parse(parameters).State);
    }
}
