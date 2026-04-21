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
        // RFC 8414 §2 requires absent optional fields — "null" is not compliant.
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

        // No field should appear as null — absent is correct, null is spec violation.
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

    [Fact]
    public void MtlsAliases_NullableFieldsOmittedWhenNull()
    {
        var aliases = new MtlsAliases(); // all properties null

        var json = JsonSerializer.Serialize(aliases, BuildOptions());

        Assert.DoesNotContain(":null", json);
    }
}
