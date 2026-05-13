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

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Verifies that <see cref="ClientJwksConfigurationExtensions"/> populates
/// <c>ClientInfo.Jwks</c> from configuration sections the standard binder leaves
/// unbound, dispatches the correct concrete <c>JsonWebKey</c> subtype by <c>kty</c>,
/// and stays a no-op when the host has already supplied <c>Jwks</c>.
/// </summary>
public class ClientJwksConfigurationExtensionsTests
{
    [Fact]
    public void AssignsJwks_WhenSectionPresentAndJwksNull()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "test-client",
                  "Jwks": {
                    "Keys": [
                      {
                        "kty": "RSA",
                        "kid": "k1",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "AQAB",
                        "e": "AQAB"
                      }
                    ]
                  }
                }
              ]
            }
            """;
        var clients = ApplyConfig(json, new ClientInfo("test-client"));

        var jwks = clients.Single().Jwks;
        Assert.NotNull(jwks);
        var key = Assert.IsType<RsaJsonWebKey>(jwks.Keys.Single());
        Assert.Equal("k1", key.KeyId);
        Assert.Equal("sig", key.Usage);
        Assert.Equal("RS256", key.Algorithm);
    }

    [Fact]
    public void SkipsAssignment_WhenJwksAlreadyPopulated()
    {
        var existing = new JsonWebKeySet([new RsaJsonWebKey { KeyId = "preset" }]);
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "test-client",
                  "Jwks": {
                    "Keys": [
                      { "kty": "RSA", "kid": "would-be-overwritten", "n": "AQAB", "e": "AQAB" }
                    ]
                  }
                }
              ]
            }
            """;
        var clients = ApplyConfig(json, new ClientInfo("test-client") { Jwks = existing });

        Assert.Same(existing, clients.Single().Jwks);
        Assert.Equal("preset", clients.Single().Jwks!.Keys.Single().KeyId);
    }

    [Fact]
    public void SkipsAssignment_WhenClientIdInConfigHasNoMatchInOptions()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "config-only-client",
                  "Jwks": {
                    "Keys": [{ "kty": "RSA", "kid": "k1", "n": "AQAB", "e": "AQAB" }]
                  }
                }
              ]
            }
            """;
        var clients = ApplyConfig(json, new ClientInfo("different-client"));

        Assert.Null(clients.Single().Jwks);
    }

    [Fact]
    public void LeavesJwksNull_WhenNoJwksSection()
    {
        const string json = """
            {
              "Clients": [
                { "ClientId": "test-client", "TokenEndpointAuthMethod": "none" }
              ]
            }
            """;
        var clients = ApplyConfig(json, new ClientInfo("test-client"));

        Assert.Null(clients.Single().Jwks);
    }

    [Fact]
    public void DispatchesByKty_ResolvesConcreteSubtypes()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "rsa-client",
                  "Jwks": {
                    "Keys": [{ "kty": "RSA", "kid": "r", "n": "AQAB", "e": "AQAB" }]
                  }
                },
                {
                  "ClientId": "ec-client",
                  "Jwks": {
                    "Keys": [
                      { "kty": "EC", "kid": "e", "crv": "P-256", "x": "AQAB", "y": "AQAB" }
                    ]
                  }
                }
              ]
            }
            """;
        var clients = ApplyConfig(json,
            new ClientInfo("rsa-client"),
            new ClientInfo("ec-client"));

        var rsa = clients.First(c => c.ClientId == "rsa-client").Jwks!.Keys.Single();
        var ec = clients.First(c => c.ClientId == "ec-client").Jwks!.Keys.Single();
        Assert.IsType<RsaJsonWebKey>(rsa);
        Assert.IsType<EllipticCurveJsonWebKey>(ec);
    }

    [Fact]
    public void AcceptsPascalCasePropertyNames_AsWellAsLowercase()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "pascal-client",
                  "Jwks": {
                    "Keys": [
                      {
                        "Kty": "RSA",
                        "Kid": "pk",
                        "Use": "sig",
                        "Alg": "RS256",
                        "N": "AQAB",
                        "E": "AQAB"
                      }
                    ]
                  }
                }
              ]
            }
            """;
        var clients = ApplyConfig(json, new ClientInfo("pascal-client"));

        var key = Assert.IsType<RsaJsonWebKey>(clients.Single().Jwks!.Keys.Single());
        Assert.Equal("pk", key.KeyId);
    }

    [Fact]
    public void Throws_WhenJwksKtyIsUnknown()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "broken",
                  "Jwks": { "Keys": [{ "kty": "UNKNOWN_TYPE" }] }
                }
              ]
            }
            """;
        Assert.Throws<InvalidOperationException>(() => ApplyConfig(json, new ClientInfo("broken")));
    }

    [Fact]
    public void Throws_WhenJwksKtyIsMissing()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "missing-kty",
                  "Jwks": { "Keys": [{ "kid": "no-kty" }] }
                }
              ]
            }
            """;
        Assert.Throws<InvalidOperationException>(() => ApplyConfig(json, new ClientInfo("missing-kty")));
    }

    [Fact]
    public void LoadsFromAppsettingsJsonFile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"appsettings-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(path, """
                {
                  "Clients": [
                    {
                      "ClientId": "from-file-client",
                      "TokenEndpointAuthMethod": "private_key_jwt",
                      "Jwks": {
                        "Keys": [
                          {
                            "kty": "RSA",
                            "kid": "file-k1",
                            "use": "sig",
                            "alg": "PS256",
                            "n": "AQAB",
                            "e": "AQAB"
                          }
                        ]
                      }
                    }
                  ]
                }
                """);

            var config = new ConfigurationBuilder()
                .AddJsonFile(path, optional: false)
                .Build();

            var clients = new[] { new ClientInfo("from-file-client") }
                .WithJwksFromConfiguration(config.GetSection("Clients"));

            var jwks = clients.Single().Jwks;
            Assert.NotNull(jwks);
            var key = Assert.IsType<RsaJsonWebKey>(jwks.Keys.Single());
            Assert.Equal("file-k1", key.KeyId);
            Assert.Equal("PS256", key.Algorithm);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    /// <summary>
    /// Host-defined ClientInfo subtype (mirrors AuthSvc's
    /// <c>Authentication.DomainModel.Entities.ClientInfo</c> inheriting from the OIDC-Server base) —
    /// used to verify the generic extension preserves the array's runtime AND static type when
    /// consumers pass derived ClientInfo collections.
    /// </summary>
    private record DerivedTestClient(string Id) : ClientInfo(Id)
    {
        public string? ExtraProperty { get; init; }
    }

    [Fact]
    public void PreservesDerivedClientInfoArrayType()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "derived-client",
                  "Jwks": {
                    "keys": [{ "kty": "RSA", "kid": "d", "n": "AQAB", "e": "AQAB" }]
                  }
                }
              ]
            }
            """;
        var config = new ConfigurationBuilder()
            .AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(json)))
            .Build();

        var clients = new[] { new DerivedTestClient("derived-client") { ExtraProperty = "preserved" } };

        DerivedTestClient[] result = clients.WithJwksFromConfiguration(config.GetSection("Clients"));

        Assert.IsType<DerivedTestClient[]>(result);
        Assert.Same(clients, result);
        Assert.Equal("preserved", result.Single().ExtraProperty);
        Assert.NotNull(result.Single().Jwks);
    }

    [Fact]
    public void OidcOptionsWrapper_DelegatesToClientArrayExtension()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "wrap",
                  "Jwks": {
                    "Keys": [{ "kty": "RSA", "kid": "w", "n": "AQAB", "e": "AQAB" }]
                  }
                }
              ]
            }
            """;
        var config = new ConfigurationBuilder()
            .AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(json)))
            .Build();

        var opts = new OidcOptions { Clients = [new ClientInfo("wrap")] };
        opts.AddClientJwksFromConfiguration(config.GetSection("Clients"));

        var key = Assert.IsType<RsaJsonWebKey>(opts.Clients.First().Jwks!.Keys.Single());
        Assert.Equal("w", key.KeyId);
    }

    private static ClientInfo[] ApplyConfig(string json, params ClientInfo[] clients)
    {
        var config = new ConfigurationBuilder()
            .AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(json)))
            .Build();

        return clients.WithJwksFromConfiguration(config.GetSection("Clients"));
    }
}
