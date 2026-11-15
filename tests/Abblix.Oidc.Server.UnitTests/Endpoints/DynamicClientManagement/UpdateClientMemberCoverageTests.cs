// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// Holds every writable member of <see cref="ClientInfo"/>, those of the option types it nests included, to one of
/// three fates under an RFC 7592 update: taken from the registration request, kept from the stored client the host set
/// it on, or taken again from <see cref="NewClientOptions"/>. A member that ends in none of them is reset to its
/// default by every update, which is how a setting the host made on a client is silently lost: a member added to
/// <see cref="ClientInfo"/> without a decision here fails this test.
/// </summary>
public class UpdateClientMemberCoverageTests
{
    /// <summary>
    /// The members an update takes again from the host's settings for new clients, as each documents.
    /// </summary>
    private static readonly string[] TakenFromNewClientOptions =
    [
        nameof(ClientInfo.ClientAssertionAudiences),
        nameof(ClientInfo.AllowOfflineAccessWithUserAgentAccessToken),
    ];

    private static readonly NewClientOptions NewClients = new()
    {
        ClientAssertionAudiences = ClientAssertionAudiences.Issuer | ClientAssertionAudiences.AllowArray,
        AllowOfflineAccessWithUserAgentAccessToken = true,
    };

    [Fact]
    public async Task EveryClientMember_IsTakenFromTheRequest_KeptFromTheHost_OrTakenFromNewClientOptions()
    {
        var stored = Populate(new ClientInfo("client-1"), Variant.Stored);

        // Two requests differing in every member show which client members the request decides; a third changes the
        // authentication method alone, which the first two hold equal so that the certificate members are built
        var first = Populate(new ClientRegistrationRequest(), Variant.First) with
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
        };
        var second = Populate(new ClientRegistrationRequest(), Variant.Second) with
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
        };
        var third = first with { TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt };

        ClientInfo[] updated = [await UpdateAsync(stored, first), await UpdateAsync(stored, second), await UpdateAsync(stored, third)];

        var unaccounted = new List<string>();
        foreach (var path in Leaves(typeof(ClientInfo), []))
        {
            var name = string.Join(".", path.Select(property => property.Name));
            var values = updated.Select(client => Read(client, path)).ToArray();

            if (TakenFromNewClientOptions.Contains(name))
            {
                Assert.All(values, value => Assert.Equal(Read(NewClientsApplied(), path), value));
                continue;
            }

            var takenFromRequest = values.Skip(1).Any(value => !StructurallyEqual(values[0], value));
            var keptFromHost = values.All(value => StructurallyEqual(Read(stored, path), value));
            if (!takenFromRequest && !keptFromHost)
                unaccounted.Add(name);
        }

        Assert.Empty(unaccounted);
    }

    /// <summary>
    /// The values <see cref="NewClients"/> gives a client at a tenant held to no profile.
    /// </summary>
    private static ClientInfo NewClientsApplied() => new("client-1")
    {
        ClientAssertionAudiences = NewClients.ClientAssertionAudiences,
        AllowOfflineAccessWithUserAgentAccessToken = NewClients.AllowOfflineAccessWithUserAgentAccessToken,
    };

    private static async Task<ClientInfo> UpdateAsync(ClientInfo stored, ClientRegistrationRequest model)
    {
        ClientInfo? saved = null;
        var clientInfoManager = new Mock<IClientInfoManager>(MockBehavior.Strict);
        clientInfoManager
            .Setup(m => m.TryUpdateClientAsync(TestTenant.Matched, It.IsAny<RegisteredClient>(), It.IsAny<RegisteredClient>()))
            .Callback((TenantDefinition _, RegisteredClient _, RegisteredClient updated) => saved = updated.ClientInfo)
            .ReturnsAsync(true);
        var tokenService = new Mock<IRegistrationAccessTokenService>(MockBehavior.Loose);
        tokenService
            .Setup(s => s.IssueTokenAsync(
                TestTenant.Matched,
                It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(), It.IsAny<string>()))
            .ReturnsAsync("registration-access-token");
        var idGenerator = new Mock<ITokenIdGenerator>(MockBehavior.Strict);
        idGenerator.Setup(g => g.GenerateTokenId()).Returns("new-jti");
        var processor = new UpdateClientRequestProcessor(
            clientInfoManager.Object, tokenService.Object, idGenerator.Object, TimeProvider.System, NewClients);

        await processor.ProcessAsync(
            SingleIssuer.Tenant,
            new ValidUpdateClientRequest(
                new UpdateClientRequest(new ClientRequest(), model), new RegisteredClient(stored, "jti-current"), model));

        return Assert.IsType<ClientInfo>(saved);
    }

    private enum Variant
    {
        First,
        Second,
        Stored,
    }

    /// <summary>
    /// The writable members of <paramref name="type"/>, as paths, descending into the option types this library nests
    /// in a client.
    /// </summary>
    private static IEnumerable<PropertyInfo[]> Leaves(Type type, PropertyInfo[] prefix)
    {
        foreach (var property in Writable(type))
        {
            PropertyInfo[] path = [..prefix, property];
            if (IsNested(property.PropertyType))
            {
                foreach (var leaf in Leaves(Underlying(property.PropertyType), path))
                    yield return leaf;
            }
            else
            {
                yield return path;
            }
        }
    }

    private static IEnumerable<PropertyInfo> Writable(Type type)
        => type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(property => property is { CanRead: true, SetMethod.IsPublic: true });

    private static bool IsNested(Type type)
    {
        var underlying = Underlying(type);
        return underlying is { IsEnum: false, IsArray: false, Namespace: not null } &&
               underlying.Namespace.StartsWith("Abblix.Oidc.Server", StringComparison.Ordinal);
    }

    private static Type Underlying(Type type) => Nullable.GetUnderlyingType(type) ?? type;

    private static object? Read(object? instance, PropertyInfo[] path)
    {
        foreach (var property in path)
            instance = instance is null ? null : property.GetValue(instance);

        return instance;
    }

    /// <summary>
    /// <paramref name="instance"/> with every writable member set to a value of <paramref name="variant"/>, each
    /// different from the member's default.
    /// </summary>
    private static T Populate<T>(T instance, Variant variant) where T : notnull
    {
        object boxed = instance;
        foreach (var property in Writable(typeof(T)))
            property.SetValue(boxed, Generate(property.PropertyType, property.GetValue(boxed), property.Name, variant));

        return (T)boxed;
    }

    private static object Generate(Type type, object? current, string name, Variant variant)
    {
        var underlying = Underlying(type);

        if (IsNested(underlying))
        {
            var nested = Create(underlying, name);
            var populate = typeof(UpdateClientMemberCoverageTests)
                .GetMethod(nameof(Populate), BindingFlags.NonPublic | BindingFlags.Static)!
                .MakeGenericMethod(underlying);
            return populate.Invoke(null, [nested, variant])!;
        }

        if (underlying.IsEnum)
        {
            var defined = Enum.GetValues(underlying).Cast<object>().Where(value => !value.Equals(current)).ToArray();
            return defined[(int)variant % defined.Length];
        }

        if (underlying == typeof(string))
            return $"{name}-{variant}";

        if (underlying == typeof(bool))
            return variant switch
            {
                Variant.First => true,
                Variant.Second => false,
                Variant.Stored => current is not true,
                _ => throw new ArgumentOutOfRangeException(nameof(variant)),
            };

        if (underlying == typeof(int))
            return (current as int? ?? 0) + 7 + (int)variant;

        if (underlying == typeof(TimeSpan))
            return (current as TimeSpan? ?? TimeSpan.Zero) + TimeSpan.FromSeconds(7 + (int)variant);

        if (underlying == typeof(Uri))
            return Address(name, variant);

        if (underlying == typeof(string[]) || underlying == typeof(IReadOnlyList<string>))
            return new[] { $"{name}-{variant}" };

        if (underlying == typeof(string[][]))
            return new[] { new[] { $"{name}-{variant}" } };

        if (underlying == typeof(Uri[]))
            return new[] { Address(name, variant) };

        if (underlying == typeof(ClientSecret[]))
            return new[] { new ClientSecret { Value = $"{name}-{variant}" } };

        if (underlying == typeof(JsonWebKeySet))
            return variant switch
            {
                Variant.First or Variant.Stored => new JsonWebKeySet([JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)]),
                Variant.Second => new JsonWebKeySet([]),
                _ => throw new ArgumentOutOfRangeException(nameof(variant)),
            };

        if (underlying == typeof(IDictionary<string, JsonElement>))
            return new Dictionary<string, JsonElement>();

        throw new InvalidOperationException($"No value is generated for {name} of type {type}");
    }

    private static Uri Address(string name, Variant variant)
        => new($"https://{name.ToLowerInvariant()}-{variant.ToString().ToLowerInvariant()}.example.com/");

    /// <summary>
    /// An instance of a nested option type, its constructor given placeholder values the population replaces.
    /// </summary>
    private static object Create(Type type, string name)
    {
        var constructor = type.GetConstructors().OrderBy(candidate => candidate.GetParameters().Length).First();
        var arguments = constructor.GetParameters()
            .Select(parameter => parameter.HasDefaultValue
                ? parameter.DefaultValue
                : Generate(parameter.ParameterType, null, name, Variant.Stored))
            .ToArray();
        return constructor.Invoke(arguments);
    }

    private static bool StructurallyEqual(object? left, object? right)
    {
        if (left is IEnumerable leftItems and not string && right is IEnumerable rightItems and not string)
        {
            var leftList = leftItems.Cast<object?>().ToList();
            var rightList = rightItems.Cast<object?>().ToList();
            return leftList.Count == rightList.Count &&
                   leftList.Zip(rightList).All(pair => StructurallyEqual(pair.First, pair.Second));
        }

        return Equals(left, right);
    }
}
