// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using Abblix.Utils.Validation;

// Aliased because .NET ships its own AllowedValuesAttribute in System.ComponentModel.DataAnnotations, and
// an unqualified name here binds to whichever is in scope. The two are not interchangeable: the framework's
// judges a single value against a set of objects, this one also flattens arrays and arrays of arrays, which
// is the shape a response_type or scope list arrives in.
using AllowedValuesAttribute = Abblix.Utils.Validation.AllowedValuesAttribute;

namespace Abblix.Utils.UnitTests;

/// <summary>
/// The three validation attributes, each on the shapes a request can actually carry.
/// </summary>
/// <remarks>
/// These decide whether a value that arrived from outside is allowed to go further, and they had no tests
/// of their own. An attribute that accepts what it should refuse fails silently by construction: the
/// request proceeds, and whatever the value breaks does so somewhere else entirely.
/// Each case below is a value shape a real request produces - a missing member, an empty string, a
/// relative address, an array with a hole in it - rather than a sampling of the type system.
/// </remarks>
public class ValidationAttributeTests
{
    /// <summary>
    /// A reflection target, not a subject: the attributes read the member's own metadata to name it in a
    /// refusal, so the test needs one member carrying a wire name and one without. The values are never
    /// read - what is validated is passed to the attribute directly.
    /// </summary>
    private sealed class Model
    {
        [JsonPropertyName("redirect_uri")]
        public string? RedirectUri { get; init; } = null;

        public string? Undecorated { get; init; } = null;
    }

    private static ValidationContext ContextFor(string memberName)
        => new(new Model()) { MemberName = memberName, DisplayName = memberName };

    private static ValidationResult? Validate(ValidationAttribute attribute, object? value, string member)
        => attribute.GetValidationResult(value, ContextFor(member));

    /// <summary>
    /// An absent or empty value is not the concern of this attribute: whether a member is required is a
    /// separate question, asked by a separate attribute, and answering it here would refuse a request that
    /// simply left an optional member out.
    /// </summary>
    [Fact]
    public void AnAbsoluteUri_TreatsAbsenceAsSomeoneElsesQuestion()
    {
        var attribute = new AbsoluteUriAttribute();

        Assert.Null(Validate(attribute, null, nameof(Model.Undecorated)));
        Assert.Null(Validate(attribute, string.Empty, nameof(Model.Undecorated)));
        Assert.Null(Validate(attribute, new Uri(string.Empty, UriKind.Relative), nameof(Model.Undecorated)));
    }

    [Fact]
    public void AnAbsoluteUri_AcceptsAnAbsoluteAddressAsStringOrUri()
    {
        var attribute = new AbsoluteUriAttribute();

        Assert.Null(Validate(attribute, "https://client.example.com/cb", nameof(Model.Undecorated)));
        Assert.Null(Validate(attribute, new Uri("https://client.example.com/cb"), nameof(Model.Undecorated)));
    }

    [Fact]
    public void AnAbsoluteUri_RefusesARelativeAddress()
    {
        var attribute = new AbsoluteUriAttribute();

        var result = Validate(attribute, "/callback", nameof(Model.Undecorated));

        Assert.NotNull(result);
        Assert.Contains("not absolute", result.ErrorMessage, StringComparison.Ordinal);
    }

    /// <summary>
    /// When a scheme is demanded, another one is refused by name. This is the check behind "https only",
    /// so the case that matters is the one where the address is perfectly well formed and simply plain.
    /// </summary>
    [Fact]
    public void AnAbsoluteUri_RefusesAnotherSchemeWhenOneIsDemanded()
    {
        var attribute = new AbsoluteUriAttribute(Uri.UriSchemeHttps);

        Assert.Null(Validate(attribute, "https://client.example.com/cb", nameof(Model.Undecorated)));

        var result = Validate(attribute, "http://client.example.com/cb", nameof(Model.Undecorated));
        Assert.NotNull(result);
        Assert.Contains("https", result.ErrorMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void AnAbsoluteUri_RefusesAValueThatIsNotAnAddressAtAll()
    {
        var attribute = new AbsoluteUriAttribute();

        var result = Validate(attribute, 42, nameof(Model.Undecorated));

        Assert.NotNull(result);
        Assert.Contains(nameof(Int32), result.ErrorMessage, StringComparison.Ordinal);
    }

    /// <summary>
    /// The message names the member as it appears on the wire, not as it is spelled in C#.
    /// </summary>
    /// <remarks>
    /// A refusal is read by whoever sent the request, and they sent <c>redirect_uri</c>. Naming the
    /// property instead would describe an object they have never seen.
    /// </remarks>
    [Fact]
    public void AnAbsoluteUri_NamesTheMemberByItsWireName()
    {
        var result = Validate(new AbsoluteUriAttribute(), "/callback", nameof(Model.RedirectUri));

        Assert.NotNull(result);
        Assert.Contains("redirect_uri", result.ErrorMessage, StringComparison.Ordinal);
    }

    /// <summary>
    /// The values guarded here are protocol names from IANA registries, and those are case-sensitive - the
    /// registration template in RFC 7636 section 6.2.1 says so in as many words. A differently-cased value is
    /// therefore a value the client did not send, not the same one written another way.
    /// </summary>
    [Theory]
    [InlineData("code", true)]
    [InlineData("CODE", false)]
    public void AllowedValues_AcceptsOnlyTheExactSpelling(string value, bool accepted)
    {
        var result = Validate(new AllowedValuesAttribute("code", "id_token"), value, nameof(Model.Undecorated));

        Assert.Equal(accepted, result is null);
    }

    /// <summary>
    /// An absent value is not this attribute's concern: nearly every parameter it guards is OPTIONAL on the
    /// wire, and refusing absence would turn every one of them into a required parameter.
    /// </summary>
    [Fact]
    public void AllowedValues_AcceptsAnAbsentValue()
        => Assert.Null(Validate(
            new AllowedValuesAttribute("code", "id_token"), null, nameof(Model.Undecorated)));

    [Fact]
    public void AllowedValues_RefusesWhatIsNot_AndSaysWhich()
    {
        var attribute = new AllowedValuesAttribute("code", "id_token");

        var result = Validate(attribute, "token", nameof(Model.Undecorated));

        Assert.NotNull(result);
        Assert.Contains("token", result.ErrorMessage, StringComparison.Ordinal);
    }

    /// <summary>
    /// An array is judged element by element, and one disallowed entry refuses the whole value - a request
    /// asking for two things gets neither when it may only have one of them.
    /// </summary>
    [Fact]
    public void AllowedValues_JudgesEveryElementOfAnArray()
    {
        var attribute = new AllowedValuesAttribute("code", "id_token");

        Assert.Null(Validate(attribute, new[] { "code", "id_token" }, nameof(Model.Undecorated)));
        Assert.NotNull(Validate(attribute, new[] { "code", "token" }, nameof(Model.Undecorated)));
    }

    /// <summary>
    /// The nested shape is the one a response_type list takes: several requests, each of several values.
    /// </summary>
    [Fact]
    public void AllowedValues_FlattensAnArrayOfArrays()
    {
        var attribute = new AllowedValuesAttribute("code", "id_token");

        Assert.Null(Validate(
            attribute,
            new[] { new[] { "code" }, new[] { "id_token", "code" } },
            nameof(Model.Undecorated)));

        Assert.NotNull(Validate(
            attribute,
            new[] { new[] { "code" }, new[] { "token" } },
            nameof(Model.Undecorated)));
    }

    /// <summary>
    /// A type the attribute cannot judge is a wiring mistake rather than a bad request, so it throws
    /// instead of quietly reporting success on a value it never looked at.
    /// </summary>
    [Fact]
    public void AllowedValues_ThrowsOnATypeItCannotJudge()
        => Assert.Throws<InvalidOperationException>(
            () => Validate(new AllowedValuesAttribute("code"), 42, nameof(Model.Undecorated)));

    [Fact]
    public void ElementsRequired_RefusesACollectionWithAHoleInIt()
    {
        var attribute = new ElementsRequiredAttribute();

        Assert.True(attribute.IsValid(new[] { "a", "b" }));
        Assert.False(attribute.IsValid(new[] { "a", null }));
        Assert.True(attribute.IsValid(Array.Empty<string>()));
    }

    /// <summary>
    /// Anything that is not a collection is not this attribute's business, including a bare value and an
    /// absent one.
    /// </summary>
    [Fact]
    public void ElementsRequired_LeavesANonCollectionAlone()
    {
        var attribute = new ElementsRequiredAttribute();

        Assert.True(attribute.IsValid(42));
        Assert.True(attribute.IsValid(null));
    }

    [Fact]
    public void ElementsRequired_NamesTheMemberInItsMessage()
        => Assert.Contains(
            "redirect_uris",
            new ElementsRequiredAttribute().FormatErrorMessage("redirect_uris"),
            StringComparison.Ordinal);
}
