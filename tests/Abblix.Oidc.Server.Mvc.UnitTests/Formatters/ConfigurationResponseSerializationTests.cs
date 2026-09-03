// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Abblix.Oidc.Server.Model;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Formatters;

public class ConfigurationResponseSerializationTests
{
    private static JsonSerializerOptions BuildOptions()
    {
        var options = new JsonSerializerOptions();
        options.TypeInfoResolverChain.Add(
            new DefaultJsonTypeInfoResolver { Modifiers = { JsonIgnoreNullsModifier.Apply } });
        return options;
    }

    [Fact]
    public void ConfigurationResponse_NullableFieldsOmittedWhenNull()
    {
        // All nullable fields intentionally left at their default (null).
        // RFC 8414 section 2 requires absent optional fields - "null" is not compliant.
        var response = new ConfigurationResponse
        {
            Issuer = "https://example.com",
            ScopesSupported = ["openid"],
            ClaimsSupported = ["sub"],
            GrantTypesSupported = ["authorization_code"],
            ResponseTypesSupported = ["code"],
            ResponseModesSupported = ["query"],
            TokenEndpointAuthMethodsSupported = ["client_secret_post"],
            IdTokenSigningAlgValuesSupported = ["RS256"],
            SubjectTypesSupported = ["public"],
            CodeChallengeMethodsSupported = ["S256"],
            PromptValuesSupported = ["login"],
        };

        var json = JsonSerializer.Serialize(response, BuildOptions());

        // No field should appear as null - absent is correct, null is spec violation.
        // System.Text.Json uses compact format: ":null" without spaces.
        Assert.DoesNotContain(":null", json);
    }

    [Fact]
    public void ConfigurationResponse_Rfc9207FlagSerializes()
    {
        var response = new ConfigurationResponse
        {
            Issuer = "https://example.com",
            ScopesSupported = ["openid"],
            ClaimsSupported = ["sub"],
            GrantTypesSupported = ["authorization_code"],
            ResponseTypesSupported = ["code"],
            ResponseModesSupported = ["query"],
            TokenEndpointAuthMethodsSupported = ["client_secret_post"],
            IdTokenSigningAlgValuesSupported = ["RS256"],
            SubjectTypesSupported = ["public"],
            CodeChallengeMethodsSupported = ["S256"],
            PromptValuesSupported = ["login"],
            AuthorizationResponseIssParameterSupported = true,
        };

        var json = JsonSerializer.Serialize(response, BuildOptions());

        Assert.Contains("\"authorization_response_iss_parameter_supported\":true", json);
    }

    /// <summary>
    /// A provider that states only what OpenID Connect Discovery 1.0 section 3 makes REQUIRED produces a document
    /// carrying exactly those fields, with the optional ones absent rather than empty.
    /// </summary>
    /// <remarks>
    /// This guards the choice made when the eleven always-present members were split by the specification's own
    /// markers: the optional ones became nullable rather than defaulting to an empty collection. The difference is
    /// visible on the wire and it changes meaning. An omitted <c>grant_types_supported</c> tells a client to apply
    /// the default that section defines, authorization code and implicit; an empty array tells it this provider
    /// accepts no grant at all. Give those members an empty-collection initialiser and this test goes red on the
    /// field it would start emitting.
    /// </remarks>
    [Fact]
    public void ConfigurationResponse_StatingOnlyTheRequiredFieldsOmitsTheOptionalOnes()
    {
        var response = new ConfigurationResponse
        {
            Issuer = "https://example.com",
            ResponseTypesSupported = ["code"],
            IdTokenSigningAlgValuesSupported = ["RS256"],
            SubjectTypesSupported = ["public"],
        };

        var json = JsonSerializer.Serialize(response, BuildOptions());

        Assert.DoesNotContain(":null", json);
        Assert.DoesNotContain("[]", json);
        Assert.DoesNotContain(ConfigurationResponse.Parameters.GrantTypesSupported, json);
        Assert.DoesNotContain(ConfigurationResponse.Parameters.ScopesSupported, json);
        Assert.DoesNotContain(ConfigurationResponse.Parameters.ResponseModesSupported, json);
        Assert.DoesNotContain(ConfigurationResponse.Parameters.TokenEndpointAuthMethodsSupported, json);

        Assert.Contains(ConfigurationResponse.Parameters.Issuer, json);
        Assert.Contains(ConfigurationResponse.Parameters.ResponseTypesSupported, json);
        Assert.Contains(ConfigurationResponse.Parameters.IdTokenSigningAlgValuesSupported, json);
        Assert.Contains(ConfigurationResponse.Parameters.SubjectTypesSupported, json);
    }

    [Fact]
    public void MtlsAliases_NullableFieldsOmittedWhenNull()
    {
        var aliases = new MtlsAliases(); // all properties null

        var json = JsonSerializer.Serialize(aliases, BuildOptions());

        Assert.DoesNotContain(":null", json);
    }
}
