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

using System.Globalization;
using System.Net.Http.Headers;
using Abblix.Oidc.Server.Mvc.Binders;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Binders;

/// <summary>
/// What the model binders do with a value they cannot turn into the model, and with the ordinary value they
/// can.
/// </summary>
/// <remarks>
/// Each of these binders converts one protocol parameter, and each has a path for a value it cannot use. Those
/// paths had no test in either direction: neither that the binder refuses, nor that a good value still binds.
/// Both halves matter and for opposite reasons - a binder that accepted an unusable value would hand the
/// endpoint a half-built request to act on, and one that refused a good value would reject conforming clients.
///
/// Two distinct refusals live here, and they were easy to conflate. A parameter that arrives more than once -
/// which OpenID Connect Core 1.0 section 3.1.2.1 forbids - does NOT reach the binder as an absent value:
/// StringValues joins multiple entries with a comma, so "en-US" and "fr-FR" arrive as the single string
/// "en-US,fr-FR" (measured), and the binder refuses it by failing to parse. The absent-value path is reached
/// only by a value provider holding no entries at all. Asserting the first and claiming to have covered the
/// second is exactly the mistake these tests were rewritten to stop making.
/// </remarks>
public class ModelBinderRefusalTests
{
    /// <summary>
    /// The locale binder handles the parameter as a single culture, an array, or a list - three separate
    /// conversions, each reached by the model type the endpoint declares.
    /// </summary>
    [Fact]
    public async Task The_locale_binder_converts_a_single_culture_an_array_and_a_list()
    {
        var binder = new CultureInfoBinder();

        var single = await ModelBinderRunner.BindAsync(binder, typeof(CultureInfo), "en-US");
        Assert.True(single.IsModelSet);
        Assert.Equal("en-US", Assert.IsType<CultureInfo>(single.Model).Name);

        var array = await ModelBinderRunner.BindAsync(binder, typeof(CultureInfo[]), "en-US", "fr-FR");
        Assert.True(array.IsModelSet);
        Assert.Equal(["en-US", "fr-FR"], Assert.IsType<CultureInfo[]>(array.Model).Select(c => c.Name));

        var list = await ModelBinderRunner.BindAsync(binder, typeof(List<CultureInfo>), "en-US", "fr-FR");
        Assert.True(list.IsModelSet);
        Assert.Equal(["en-US", "fr-FR"], Assert.IsType<List<CultureInfo>>(list.Model).Select(c => c.Name));
    }

    /// <summary>
    /// Asking for one culture and receiving two: the two arrive joined, no culture is named "en-US,fr-FR", and
    /// the binder records the failure instead of binding one of them. Which one it might have picked is the
    /// point - a silent choice here decides the language the end user is shown.
    /// </summary>
    [Fact]
    public async Task The_locale_binder_records_a_failure_when_one_culture_is_expected_and_two_arrive()
    {
        var outcome = await ModelBinderRunner.BindAsync(
            new CultureInfoBinder(), typeof(CultureInfo), "en-US", "fr-FR");

        Assert.False(outcome.IsModelSet);
        Assert.False(outcome.ModelState.IsValid);
    }

    /// <summary>
    /// With no value at all the binder leaves the model unset and records nothing - an omitted optional
    /// parameter simply stays absent, and recording an error would turn every omission into a rejected request.
    /// </summary>
    /// <remarks>
    /// The absence is handled by the base binder, before the parameter-specific conversion runs: it returns as
    /// soon as the value provider reports nothing, so the conversion never sees an empty value. That is
    /// asserted here through the model state, which stays untouched precisely because the value was never
    /// recorded - and it is the reason each of these three binders carries an unreachable "no value" guard of
    /// its own. Measured rather than assumed: with the guards in place, this case leaves them untaken.
    /// </remarks>
    [Fact]
    public async Task A_binder_given_no_value_leaves_the_model_unset_and_records_nothing()
    {
        foreach (var (binder, modelType) in new (Microsoft.AspNetCore.Mvc.ModelBinding.IModelBinder, Type)[]
                 {
                     (new CultureInfoBinder(), typeof(CultureInfo)),
                     (new JsonSerializerModelBinder(), typeof(string[])),
                     (new SecondsToTimeSpanModelBinder(), typeof(TimeSpan)),
                 })
        {
            var outcome = await ModelBinderRunner.BindAsync(binder, modelType);

            Assert.False(outcome.IsModelSet);
            Assert.True(outcome.ModelState.IsValid);
            Assert.Empty(outcome.ModelState);
        }
    }

    /// <summary>
    /// The JSON-valued parameters - <c>claims</c> among them - go through a binder that deserializes. Two
    /// values joined by a comma are not a JSON document, so the request is refused rather than acted on as a
    /// claims request the client did not make.
    /// </summary>
    [Fact]
    public async Task The_json_binder_deserializes_one_value_and_records_a_failure_when_two_arrive()
    {
        var binder = new JsonSerializerModelBinder();

        var bound = await ModelBinderRunner.BindAsync(binder, typeof(string[]), """["a","b"]""");
        Assert.True(bound.IsModelSet);
        Assert.Equal(["a", "b"], Assert.IsType<string[]>(bound.Model));

        var repeated = await ModelBinderRunner.BindAsync(binder, typeof(string[]), """["a"]""", """["b"]""");
        Assert.False(repeated.IsModelSet);
        Assert.False(repeated.ModelState.IsValid);
    }

    /// <summary>
    /// The lifetime parameters arrive as a count of seconds. Two of them joined are not a number, and this
    /// refusal matters beyond binding: a lifetime picked from two candidates is a token living longer than the
    /// client asked for.
    /// </summary>
    [Fact]
    public async Task The_seconds_binder_converts_one_value_and_records_a_failure_when_two_arrive()
    {
        var binder = new SecondsToTimeSpanModelBinder();

        var bound = await ModelBinderRunner.BindAsync(binder, typeof(TimeSpan), "300");
        Assert.True(bound.IsModelSet);
        Assert.Equal(TimeSpan.FromMinutes(5), bound.Model);

        var repeated = await ModelBinderRunner.BindAsync(binder, typeof(TimeSpan), "300", "600");
        Assert.False(repeated.IsModelSet);
        Assert.False(repeated.ModelState.IsValid);
    }

    /// <summary>
    /// A value the header grammar cannot parse is refused rather than passed along as something the endpoint
    /// would read as a credential.
    /// </summary>
    /// <remarks>
    /// The cases are chosen from what the grammar actually rejects, which is narrower than it looks: a scheme
    /// is any token, so "this is not a header value" parses happily as the scheme "this" with the rest as its
    /// parameter (measured). What fails is an empty value, or a first token that is not a token at all - a
    /// comma or an equals sign inside it, or non-ASCII. Writing this test from the phrase that reads most
    /// obviously wrong would have asserted a refusal that never happens.
    /// </remarks>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("=bad")]
    [InlineData("Bearer,token")]
    public async Task The_authorization_header_binder_refuses_a_value_the_grammar_rejects(string headerValue)
    {
        var outcome = await ModelBinderRunner.BindHeaderAsync(
            new AuthenticationHeaderBinder(), typeof(AuthenticationHeaderValue), "Authorization", headerValue);

        Assert.False(outcome.IsModelSet);
    }

    /// <summary>
    /// And the ordinary case, so the refusal above means something: a well-formed header binds to its scheme
    /// and parameter.
    /// </summary>
    [Fact]
    public async Task The_authorization_header_binder_binds_a_well_formed_header()
    {
        var outcome = await ModelBinderRunner.BindHeaderAsync(
            new AuthenticationHeaderBinder(), typeof(AuthenticationHeaderValue),
            "Authorization", "Bearer some-token");

        Assert.True(outcome.IsModelSet);
        var header = Assert.IsType<AuthenticationHeaderValue>(outcome.Model);
        Assert.Equal("Bearer", header.Scheme);
        Assert.Equal("some-token", header.Parameter);
    }
}
