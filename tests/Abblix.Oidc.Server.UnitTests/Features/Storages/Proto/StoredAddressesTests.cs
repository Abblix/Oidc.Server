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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Storages.Proto.Mappers;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Xunit;
using StoredBackChannelRequest = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationRequest;
using StoredDeviceRequest = Abblix.Oidc.Server.Features.DeviceAuthorization.DeviceAuthorizationRequest;

namespace Abblix.Oidc.Server.UnitTests.Features.Storages.Proto;

/// <summary>
/// Every address a stored record carries reads back exactly as it was written, so what the server sends on - a
/// token's audience, a redirect, a notification - names it as the client registered it, not in a canonical form
/// with a slash added, the host's case changed or its port dropped. The addresses are found on each record by type,
/// so one added later is held to the same rule; one the store does not keep, such as an address the server sets
/// after reading the record, reads back empty and is not this test's subject.
/// </summary>
public class StoredAddressesTests
{
    private const string Written = "https://Client.Example.com:443/a%20b";

    [Fact]
    public void AnAuthorizationContext_KeepsEveryAddressAsWritten()
    {
        var context = WithEveryAddress(new AuthorizationContext("client", [Scopes.OpenId], null));

        AssertEveryAddressAsWritten(AuthorizationContextMapper.FromProto(context.ToProto()));
    }

    [Fact]
    public void AnAuthorizationRequest_KeepsEveryAddressAsWritten()
    {
        var request = WithEveryAddress(new AuthorizationRequest());

        AssertEveryAddressAsWritten(request.ToProto().FromProto());
    }

    [Fact]
    public void ABackChannelRequest_KeepsEveryAddressAsWritten()
    {
        var grant = new AuthorizedGrant(
            new AuthSession("subject", "session", DateTimeOffset.UnixEpoch, "local"),
            new AuthorizationContext("client", [Scopes.OpenId], null));
        var request = WithEveryAddress(new StoredBackChannelRequest(grant, DateTimeOffset.UnixEpoch));

        AssertEveryAddressAsWritten(request.ToProto().FromProto());
    }

    [Fact]
    public void ADeviceRequest_KeepsEveryAddressAsWritten()
    {
        var request = WithEveryAddress(new StoredDeviceRequest("client", [Scopes.OpenId], null, "USERCODE"));

        AssertEveryAddressAsWritten(request.ToProto().FromProto());
    }

    private static PropertyInfo[] Addresses<T>() => typeof(T)
        .GetProperties(BindingFlags.Public | BindingFlags.Instance)
        .Where(property => property.CanWrite &&
                           (property.PropertyType == typeof(Uri) || property.PropertyType == typeof(Uri[])))
        .ToArray();

    private static T WithEveryAddress<T>(T record)
    {
        var addresses = Addresses<T>();
        Assert.NotEmpty(addresses);

        foreach (var property in addresses)
        {
            property.SetValue(record, property.PropertyType == typeof(Uri)
                ? new Uri(Written)
                : new[] { new Uri(Written) });
        }

        return record;
    }

    private static void AssertEveryAddressAsWritten<T>(T record)
    {
        var stored = (
            from property in Addresses<T>()
            let value = property.GetValue(record)
            where value is not null
            select (property.Name, Address: value as Uri ?? Assert.Single(Assert.IsType<Uri[]>(value)))
        ).ToArray();

        Assert.NotEmpty(stored);
        foreach (var (name, address) in stored)
        {
            Assert.True(
                address.OriginalString == Written,
                $"{typeof(T).Name}.{name} reads back as '{address.OriginalString}'");
        }
    }
}
