// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Reflection;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Every URI a registration can carry is refused when it is relative - found by TYPE, not by a list.
/// </summary>
/// <remarks>
/// <see cref="StoredUriValidator"/> names its members one by one, which is what makes it readable and
/// what makes it able to fall behind: it did, twice, first by six members that had no validator at all
/// and then by three more whose validator was gated on something that is not the address. This row is
/// the half that cannot fall behind, because it asks the MODEL what its URI members are.
/// <para>
/// It drives the validator rather than reading an annotation. A row that checked for a marker attribute
/// would prove only that the marker is present - and if the validator read the same marker, the two
/// would agree with each other while agreeing about nothing that runs.
/// </para>
/// </remarks>
public class UriMemberCoverageTests
{
    private static readonly Uri Relative = new("/somewhere", UriKind.Relative);

    public static TheoryData<string> UriMembers()
    {
        var data = new TheoryData<string>();

        foreach (var property in UriProperties())
            data.Add(property.Name);

        return data;
    }

    private static PropertyInfo[] UriProperties() => typeof(ClientRegistrationRequest)
        .GetProperties(BindingFlags.Public | BindingFlags.Instance)
        .Where(property => property.PropertyType == typeof(Uri) || property.PropertyType == typeof(Uri[]))
        .ToArray();

    [Theory]
    [MemberData(nameof(UriMembers))]
    public async Task EveryUriMemberIsRefusedWhenRelative(string memberName)
    {
        var property = Array.Find(UriProperties(), p => p.Name == memberName);
        Assert.NotNull(property);

        var request = new ClientRegistrationRequest { RedirectUris = [] };
        property.SetValue(
            request,
            property.PropertyType == typeof(Uri[]) ? new[] { Relative } : Relative);

        var result = await new StoredUriValidator().ValidateAsync(new ClientRegistrationValidationContext(request));

        Assert.NotNull(result);

        // The NAME as well as the refusal. The validator is fourteen hand-written (name, value) pairs and
        // its summary promises an error naming the member - measured, swapping two pairs left both suites
        // green while an operator sending a relative policy_uri was told about their tos_uri.
        Assert.Contains(
            ParameterNameOf(property),
            result.ErrorDescription,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The registration parameter a property is reported by, taken from the model's own JSON name.
    /// </summary>
    private static string ParameterNameOf(PropertyInfo property)
        => property.GetCustomAttribute<JsonPropertyNameAttribute>()?.Name ?? property.Name;

    /// <summary>
    /// The control: the same request with every URI member absolute is accepted, so the rows above
    /// measure the relative value rather than a validator that refuses whatever it is given.
    /// </summary>
    [Fact]
    public async Task AnAbsoluteValueInEveryMemberIsAccepted()
    {
        var absolute = new Uri("https://client.example.com/x");
        var request = new ClientRegistrationRequest { RedirectUris = [] };

        var properties = UriProperties();

        // And the control on the control: a walk that found nothing would accept the request trivially
        // and read exactly like a model with no URI members at all.
        Assert.NotEmpty(properties);

        foreach (var property in properties)
        {
            property.SetValue(
                request,
                property.PropertyType == typeof(Uri[]) ? new[] { absolute } : absolute);
        }

        var result = await new StoredUriValidator().ValidateAsync(new ClientRegistrationValidationContext(request));

        Assert.Null(result);
    }
}
