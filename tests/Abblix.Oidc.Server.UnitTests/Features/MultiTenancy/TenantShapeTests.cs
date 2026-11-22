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
using System.Security.Cryptography;
using System.Text;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.MultiTenancy;

/// <summary>
/// A null wherever a tenant's definition holds a value - every member of every type it reaches, and every element of
/// every collection - set on a tenant otherwise whole and judged by every check the server registers.
/// </summary>
/// <remarks>
/// The places are found by walking the definition, not listed, so a member added later is driven too.
/// </remarks>
public class TenantShapeTests
{
    private const string TenantId = "acme";
    private const string OwnNamespace = "Abblix.";

    /// <summary>
    /// A null the types declare a value for refuses the tenant, and one they allow does not throw; no place makes the
    /// judgement of the list fail, which would leave every tenant unserved.
    /// </summary>
    [Theory]
    [MemberData(nameof(Places))]
    public void ANullAnywhere_IsRefusedOrAllowed_NeverThrows(Root root, string path, bool asElement)
    {
        var before = Judge(TenantOf(root)).Select(refusal => refusal.Message).ToHashSet(StringComparer.Ordinal);
        var tenant = TenantOf(root);
        var place = PlacesOf(tenant).Single(candidate => candidate.Path == path);
        var declaresValue = place.Set(asElement);

        var refusals = Judge(tenant);

        if (declaresValue)
        {
            Assert.Contains(
                refusals,
                refusal => refusal.TenantIds.Contains(tenant.Id) && !before.Contains(refusal.Message));
        }
    }

    /// <summary>The whole tenants the places are set on.</summary>
    public enum Root
    {
        /// <summary>A tenant declaring its keys in its settings, refused for nothing.</summary>
        KeysInSettings,

        /// <summary>A tenant naming its keys in a custodian, refused only for the custodian no test host has.</summary>
        KeysInCustodian,
    }

    private static TenantDefinition TenantOf(Root root) => root switch
    {
        Root.KeysInSettings => Whole(),
        Root.KeysInCustodian => new TenantDefinition
        {
            Id = TenantId,
            Issuer = new Uri("https://auth.example.com"),
            CustodianKeys = new CustodianHeldKeys { SigningKeyName = "signing", EncryptionKeyName = "encryption" },
        },
        _ => throw new ArgumentOutOfRangeException(nameof(root), root, null),
    };

    /// <summary>
    /// Every place a null can stand, by its path from the tenant, once as the member itself and once as an element of
    /// a collection.
    /// </summary>
    public static TheoryData<Root, string, bool> Places()
    {
        var data = new TheoryData<Root, string, bool>();
        foreach (var root in Enum.GetValues<Root>())
        {
            foreach (var place in PlacesOf(TenantOf(root)))
                AddPlace(data, root, place);
        }

        return data;
    }

    private static void AddPlace(TheoryData<Root, string, bool> data, Root root, Place place)
    {
        if (place.CanBeNull)
            data.Add(root, place.Path, false);

        if (place.ElementCanBeNull)
            data.Add(root, place.Path, true);
    }

    /// <summary>
    /// The places the theory drives reach every type of the server's own a definition declares, so a type the whole
    /// tenant leaves out would show here rather than go undriven.
    /// </summary>
    [Fact]
    public void ThePlaces_ReachEveryOwnTypeOfTheDefinition()
    {
        var reached = Enum.GetValues<Root>()
            .SelectMany(root => PlacesOf(TenantOf(root)))
            .Select(place => place.Owner.GetType())
            .ToHashSet();

        var missing = DeclaredOwnTypes(typeof(TenantDefinition))
            .Where(type => !type.IsValueType && !reached.Any(seen => seen.IsAssignableTo(type)))
            .ToArray();

        Assert.Empty(missing);
    }

    /// <summary>
    /// The whole tenant the places are set on, and the same tenant with every member that may be null left null, are
    /// not refused for a null: the walk refuses what the types rule out and nothing they allow.
    /// </summary>
    [Fact]
    public void AWholeTenant_AndOneWithEveryOptionalMemberNull_HoldNoRefusedNull()
    {
        // Refused for nothing at all, so a refusal the theory sees is the null's
        Assert.Empty(Judge(Whole()).Select(refusal => refusal.Message));

        var sparse = Whole();
        foreach (var place in PlacesOf(sparse).Where(place => !place.DeclaresValue).Reverse())
            place.Set(asElement: false);

        Assert.Empty(TenantShape.NullsOf(sparse));
    }

    /// <summary>
    /// A refusal names the tenant, the client by its id and the member, and an element by its index.
    /// </summary>
    [Fact]
    public void ARefusal_NamesTheTenantTheClientAndTheMember()
    {
        var tenant = Whole();
        tenant.Clients.Single().ClientSecrets = [null!];
        tenant.Resources![0] = tenant.Resources[0] with { Resource = null! };

        var paths = TenantShape.NullsOf(tenant).ToArray();

        Assert.Equal(["Clients['web'].ClientSecrets[0]", "Resources[0].Resource"], paths);
    }

    private static TenantRefusal[] Judge(TenantDefinition tenant)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddOidcServices(_ => { });
        using var provider = services.BuildServiceProvider();
        return [..TenantRefusal.AllOf(provider.GetServices<ITenantsCheck>(), [tenant], new OidcOptions())];
    }

    /// <summary>
    /// A tenant with every member of every type it reaches set, keys in a custodian aside, so the places beneath each are there to be found.
    /// </summary>
    private static TenantDefinition Whole()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        key.Certificates = [[1, 2, 3]];
        var scope = new ScopeDefinition("orders", "order_id");

        return new TenantDefinition
        {
            Id = TenantId,
            Issuer = new Uri("https://auth.example.com"),
            Clients =
            [
                new ClientInfo("web")
                {
                    ClientSecrets =
                    [
                        new ClientSecret
                        {
                            Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes("secret")),
                            Value = "secret",
                            ExpiresAt = DateTimeOffset.UnixEpoch.AddYears(100),
                        },
                    ],
                    RedirectUris = [new Uri("https://client.example.com/callback")],
                    PostLogoutRedirectUris = [new Uri("https://client.example.com/")],
                    FrontChannelLogout = new FrontChannelLogoutOptions(new Uri("https://client.example.com/fc")),
                    BackChannelLogout = new BackChannelLogoutOptions(new Uri("https://client.example.com/bc")),
                    AllowedResponseTypes = [[ResponseTypes.Code]],
                    AllowedGrantTypes = [GrantTypes.AuthorizationCode],
                    AllowedResponseModes = [ResponseModes.Query],
                    Jwks = new JsonWebKeySet([key]),
                    AuthorizationDetailsTypes = ["payment"],
                    TokenExchangeAllowedSubjectTokenTypes = [new Uri("urn:ietf:params:oauth:token-type:access_token")],
                    TokenExchangeAllowedAudiences = ["https://api.example.com"],
                    ResourceLocations = [new Uri("https://api.example.com")],
                    TlsClientAuth = new TlsClientAuthOptions
                    {
                        SubjectDn = "CN=web",
                        SanDns = ["client.example.com"],
                        SanUris = [new Uri("https://client.example.com")],
                        SanIps = ["192.0.2.1"],
                        SanEmails = ["web@example.com"],
                    },
                    RequestUris = [new Uri("https://client.example.com/request")],
                    Contacts = ["admin@example.com"],
                    DefaultAcrValues = ["urn:acr:1"],
                    AllowedScopes = ["openid"],
                    AllowedResources = [new Uri("https://api.example.com")],
                    DefaultScope = ["openid"],
                },
            ],
            Scopes = [scope],
            Resources = [new ResourceDefinition(new Uri("https://api.example.com"), scope) { Jwks = new JsonWebKeySet([key]) }],
            PairwiseSubject = new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[32]) },
            SigningKeys = [key],
            EncryptionKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption)],
        };
    }

    /// <summary>
    /// A member of a reference type, or a collection, found on an object the definition holds.
    /// </summary>
    private sealed record Place(string Path, object Owner, PropertyInfo Property, NullabilityInfo Nullability)
    {
        public bool DeclaresValue => Nullability.ReadState == NullabilityState.NotNull;

        public bool CanBeNull => !Property.PropertyType.IsValueType;

        public bool ElementCanBeNull
            => ElementOf(Nullability) is { Type.IsValueType: false } && Property.PropertyType != typeof(string);

        /// <summary>
        /// Writes the null: as the member itself, or as the one element of the collection it holds. Whether the types
        /// declare a value there, and so whether the tenant has to be refused for it.
        /// </summary>
        public bool Set(bool asElement)
        {
            if (!asElement)
            {
                Property.SetValue(Owner, null);

                // A member that takes null as something else, as the generation does, holds no null to refuse
                return DeclaresValue && Property.GetValue(Owner) is null;
            }

            var element = ElementOf(Nullability)!;
            var collection = Array.CreateInstance(element.Type, 1);
            Property.SetValue(Owner, collection);
            return element.ReadState == NullabilityState.NotNull;
        }
    }

    private static IEnumerable<Place> PlacesOf(TenantDefinition tenant) => PlacesOf(tenant, string.Empty);

    private static IEnumerable<Place> PlacesOf(object owner, string path)
    {
        var context = new NullabilityInfoContext();
        foreach (var property in owner.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (!property.CanRead || !property.CanWrite || property.GetIndexParameters().Length > 0)
                continue;

            var memberPath = path.Length == 0 ? property.Name : $"{path}.{property.Name}";
            var nullability = context.Create(property);
            var value = property.GetValue(owner);

            if (!property.PropertyType.IsValueType || ElementOf(nullability) is not null)
                yield return new Place(memberPath, owner, property, nullability);

            if (value is null or string or Uri)
                continue;

            var beneath = value is IEnumerable elements
                ? elements.Cast<object?>().SelectMany((element, index) => PlacesBeneath(element, $"{memberPath}[{index}]"))
                : PlacesBeneath(value, memberPath);

            foreach (var place in beneath)
                yield return place;
        }
    }

    private static IEnumerable<Place> PlacesBeneath(object? value, string path)
        => value is not null && IsOwn(value.GetType()) && !value.GetType().IsValueType ? PlacesOf(value, path) : [];

    private static NullabilityInfo? ElementOf(NullabilityInfo collection)
        => collection.ElementType ?? (collection.GenericTypeArguments is [var element] ? element : null);

    /// <summary>
    /// Every type of the server's own reachable from <paramref name="root"/> through the declared types of its
    /// settable members and their elements.
    /// </summary>
    private static HashSet<Type> DeclaredOwnTypes(Type root)
    {
        var found = new HashSet<Type>();
        var pending = new Stack<Type>([root]);
        while (pending.TryPop(out var type))
        {
            foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                if (!property.CanWrite || property.GetIndexParameters().Length > 0)
                    continue;

                var declared = Nullable.GetUnderlyingType(property.PropertyType) ?? property.PropertyType;
                while (declared.IsArray || declared is { IsGenericType: true } && declared.GetGenericArguments().Length == 1 &&
                       declared.IsAssignableTo(typeof(IEnumerable)))
                {
                    declared = declared.IsArray ? declared.GetElementType()! : declared.GetGenericArguments()[0];
                }

                if (IsOwn(declared) && found.Add(declared))
                    pending.Push(declared);
            }
        }

        found.Remove(root);
        return found;
    }

    private static bool IsOwn(Type type)
        => !type.IsEnum && type.Namespace?.StartsWith(OwnNamespace, StringComparison.Ordinal) == true;
}
