// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Xunit;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.UnitTests.Features.MultiTenancy;

/// <summary>
/// Each setting a tenant declares has a counterpart of the same name on <see cref="OidcOptions"/>, and that
/// counterpart is refused under multi-tenancy.
/// </summary>
/// <remarks>
/// The startup checks find a tenant's settings by name: the refusal of the server-wide value, and the copy the
/// server's own checks judge for each tenant. A tenant setting with no counterpart, or one whose type the
/// counterpart cannot hold, would pass through both without a word.
/// </remarks>
public class TenantSettingsMirrorTests
{
    /// <summary>
    /// What the server's options have no counterpart for: the tenant's own name, and the pairwise key, which a
    /// server without tenants registers beside its options rather than in them.
    /// </summary>
    private static readonly HashSet<string> TenantOnly =
        [
            nameof(TenantDefinition.Id), nameof(TenantDefinition.Generation), nameof(TenantDefinition.PairwiseSubject),
            nameof(TenantDefinition.CustodianKeys), nameof(TenantDefinition.MtlsBaseUri),
        ];

    public static TheoryData<string> Mirrored => new(
        typeof(TenantDefinition).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(property => property.Name)
            .Where(name => !TenantOnly.Contains(name)));

    /// <summary>
    /// Every tenant setting but the tenant-only ones is found by the startup checks, so none is left out for a name
    /// the server's options spell otherwise or a type they cannot hold.
    /// </summary>
    [Theory]
    [MemberData(nameof(Mirrored))]
    public void ATenantSetting_IsOneTheStartupChecksFind(string setting)
        => Assert.Contains(TenantOwnedSettings.All, owned => owned.Tenant.Name == setting);

    [Theory]
    [MemberData(nameof(Mirrored))]
    public void AServerWideValueOfATenantSetting_IsRefused(string setting)
    {
        var serverProperty = typeof(OidcOptions).GetProperty(setting)!;
        var options = new OidcOptions();
        serverProperty.SetValue(options, SampleOf(serverProperty.PropertyType));

        var result = new TenantOwnedOptionsValidator().Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains($"{nameof(OidcOptions)}.{setting} applies to the whole server", result.FailureMessage,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Options that set none of the tenant's settings pass, an empty collection other than the default
    /// instance included: it declares nothing, whichever instance it is.
    /// </summary>
    [Fact]
    public void OptionsSettingNoneOfThem_PassTheCheck()
    {
        Assert.True(new TenantOwnedOptionsValidator().Validate(null, new OidcOptions()).Succeeded);
        Assert.True(new TenantOwnedOptionsValidator().Validate(null, new OidcOptions { Clients = new List<ClientInfo>() }).Succeeded);
    }

    /// <summary>
    /// A value of <paramref name="type"/> other than the one a fresh <see cref="OidcOptions"/> holds.
    /// </summary>
    private static object SampleOf(Type type)
    {
        if (type == typeof(string))
            return "https://auth.example.com";
        if (type == typeof(Uri))
            return new Uri("https://api.example.com");
        if (type.IsEnum)
            return Enum.GetValues(type).Cast<object>().Last();
        if (type.IsArray)
            return Array.CreateInstance(type.GetElementType()!, 1);
        if (type.IsAssignableFrom(typeof(ClientInfo[])))
            return new[] { new ClientInfo("client") };
        if (type.IsAssignableFrom(typeof(JsonWebKey[])))
            return new[] { JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature) };

        throw new NotSupportedException($"No sample of {type} to set; add one here.");
    }
}
