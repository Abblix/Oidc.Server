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
using System.Reflection.Emit;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Xunit;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.UnitTests.Architecture;

/// <summary>
/// A setting each tenant declares for itself is read through <see cref="IIssuerSettings"/>, never straight off
/// <see cref="OidcOptions"/>.
/// </summary>
/// <remarks>
/// Under multi-tenancy those settings are unset on <see cref="OidcOptions"/>, so code reading them there gets
/// nothing rather than the tenant's value: a tenant's security profile would silently hold nobody to anything.
/// Every reader's own tests configure one options object and see no difference, so the question is asked of the
/// compiled code instead: which methods call the getter of such a setting. The settings are the ones a
/// <see cref="TenantDefinition"/> declares under the same name, so a setting a tenant gains is covered here
/// without anybody extending a list.
/// </remarks>
public class TenantOwnedSettingsAreReadPerIssuerTests
{
    /// <summary>
    /// The readers that judge or serve the server-wide value itself.
    /// </summary>
    private static readonly HashSet<string> ServerWideReaders =
    [
        // The settings themselves and the host's helper filling them in from configuration
        typeof(OidcOptions).FullName!,
        typeof(ClientJwksConfigurationExtensions).FullName!,

        // The server without tenants: its one issuer and the settings it serves from these options
        typeof(OptionsIssuerSettings).FullName!,
        typeof(PreconfiguredIssuerProvider).FullName!,
        $"{typeof(Abblix.Oidc.Server.Features.ServiceCollectionExtensions).FullName}.{nameof(Abblix.Oidc.Server.Features.ServiceCollectionExtensions.AddIssuer)}",

        // The issuer's session cookie name, derived from the configured one
        $"{typeof(TenantIssuerSettings).FullName}.get_{nameof(TenantIssuerSettings.CheckSessionCookieName)}",
        typeof(CheckSessionCookieOptions).FullName!,

        // Startup judging the configured values
        typeof(ClientIdsOptionsValidator).FullName!,
        typeof(ClientSecretsOptionsValidator).FullName!,
        typeof(ClockSkewCeilingValidator).FullName!,
        typeof(DefaultResourceIndicatorValidator).FullName!,
        typeof(OidcOptionsSecurityProfileValidator).FullName!,
        typeof(PairwiseClientsOptionsValidator).FullName!,
        typeof(ResourceDefinitionsValidator).FullName!,
        typeof(TenantOwnedOptionsValidator).FullName!,
    ];

    [Fact]
    public void ATenantOwnedSetting_IsReadOnlyWhereTheServerWideValueIsMeant()
    {
        var getters = TenantOwnedGetters();
        Assert.NotEmpty(getters);

        var readers = (
            from assembly in Assemblies
            from method in MethodsOf(assembly)
            from called in CalledMethods(method)
            where getters.Contains(called)
            let owner = OwnerOf(method)
            let reader = $"{owner}.{OriginOf(method)}"
            where !ServerWideReaders.Contains(owner) && !ServerWideReaders.Contains(reader)
            select $"{reader} reads {called.DeclaringType!.Name}.{called.Name["get_".Length..]}"
        ).Distinct().OrderBy(line => line, StringComparer.Ordinal).ToArray();

        Assert.True(readers.Length == 0, string.Join(Environment.NewLine, readers));
    }

    /// <summary>
    /// The instrument reads what it is aimed at: a method that does read a tenant-owned setting is found.
    /// </summary>
    [Fact]
    public void TheInstrument_FindsAKnownReader()
    {
        var getters = TenantOwnedGetters();
        var reader = typeof(OptionsIssuerSettings).GetProperty(nameof(IIssuerSettings.Clients))!.GetMethod!;

        Assert.Contains(CalledMethods(reader), getters.Contains);
    }

    /// <summary>
    /// The server and the two transports built on it, where a request's settings are read.
    /// </summary>
    private static readonly Assembly[] Assemblies =
    [
        typeof(OidcOptions).Assembly,
        typeof(Abblix.Oidc.Server.AspNetCore.MultiTenancy.MultiTenancyExtensions).Assembly,
        typeof(Abblix.Oidc.Server.Mvc.Formatters.AuthorizationResponseFormatter).Assembly,
        typeof(Abblix.Oidc.Server.MinimalApi.Formatters.AuthorizationResponseFormatter).Assembly,
    ];

    private static HashSet<MethodInfo> TenantOwnedGetters()
    {
        var tenantSettings = typeof(TenantDefinition)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);

        return typeof(OidcOptions)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(property => tenantSettings.Contains(property.Name) && property.GetMethod is not null)
            .Select(property => property.GetMethod!)
            .Append(typeof(CheckSessionCookieOptions).GetProperty(nameof(CheckSessionCookieOptions.Name))!.GetMethod!)
            .ToHashSet();
    }

    /// <summary>
    /// The member a method was written in: a lambda and an async body are compiled under names that carry it.
    /// </summary>
    private static string OriginOf(MethodBase method)
    {
        var name = method.Name.StartsWith('<') ? method.Name : method.DeclaringType!.Name;
        return name.StartsWith('<') ? name[1..name.IndexOf('>')] : method.Name;
    }

    /// <summary>
    /// The type a method belongs to as a reader sees it: a lambda's closure or an async state machine is named
    /// after the type that wrote it.
    /// </summary>
    private static string OwnerOf(MethodBase method)
    {
        var type = method.DeclaringType!;
        while (type.DeclaringType is not null && type.Name.StartsWith('<'))
            type = type.DeclaringType;
        return type.FullName!;
    }

    private static IEnumerable<MethodBase> MethodsOf(Assembly assembly)
    {
        const BindingFlags all = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance |
                                 BindingFlags.Static | BindingFlags.DeclaredOnly;

        foreach (var type in assembly.GetTypes())
        {
            foreach (var method in type.GetMethods(all))
                yield return method;
            foreach (var constructor in type.GetConstructors(all))
                yield return constructor;
        }
    }

    /// <summary>
    /// The methods a method's body calls, read from its IL instruction by instruction, so an operand's bytes are
    /// never taken for an instruction.
    /// </summary>
    private static IEnumerable<MethodBase> CalledMethods(MethodBase method)
    {
        var il = method.GetMethodBody()?.GetILAsByteArray();
        if (il is null)
            yield break;

        var position = 0;
        while (position < il.Length)
        {
            var opCode = il[position] == 0xFE
                ? TwoByteOpCodes[il[position + 1]]
                : OneByteOpCodes[il[position]];
            position += opCode.Size;

            if (opCode.OperandType == OperandType.InlineMethod)
            {
                var token = BitConverter.ToInt32(il, position);
                MethodBase? called = null;
                try
                {
                    called = method.Module.ResolveMethod(
                        token,
                        method.DeclaringType?.IsGenericType == true ? method.DeclaringType.GetGenericArguments() : null,
                        method.IsGenericMethod ? method.GetGenericArguments() : null);
                }
                catch (ArgumentException)
                {
                    // A method of a generic type instantiated elsewhere; none of the getters is one.
                }

                if (called is not null)
                    yield return called;
            }

            position += OperandSize(opCode.OperandType, il, position);
        }
    }

    private static int OperandSize(OperandType operandType, byte[] il, int position) => operandType switch
    {
        OperandType.InlineNone => 0,
        OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
        OperandType.InlineVar => 2,
        OperandType.InlineI8 or OperandType.InlineR => 8,
        OperandType.InlineSwitch => 4 + 4 * BitConverter.ToInt32(il, position),
        _ => 4,
    };

    private static readonly OpCode[] OneByteOpCodes = new OpCode[0x100];
    private static readonly OpCode[] TwoByteOpCodes = new OpCode[0x100];

    static TenantOwnedSettingsAreReadPerIssuerTests()
    {
        foreach (var field in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            var opCode = (OpCode)field.GetValue(null)!;
            var value = (ushort)opCode.Value;
            if (opCode.Size == 1)
                OneByteOpCodes[value] = opCode;
            else
                TwoByteOpCodes[value & 0xFF] = opCode;
        }
    }
}
