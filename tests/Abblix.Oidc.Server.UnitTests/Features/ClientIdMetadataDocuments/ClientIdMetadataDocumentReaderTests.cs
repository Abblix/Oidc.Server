// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// What a client's metadata document is read into, and what it is refused for, by the rules
/// draft-ietf-oauth-client-id-metadata-document adds to RFC 7591 (sections 4, 4.1, 5 and 6).
/// </summary>
public class ClientIdMetadataDocumentReaderTests
{
    private const string ClientId = "https://client.example.com/metadata.json";

    private static ClientIdMetadataDocumentReader CreateReader(
        string[]? authenticationMethods = null,
        string[]? grantTypes = null,
        string[]? responseTypeParts = null,
        string[]? allowedGrantTypes = null,
        Uri[]? allowedDestinations = null,
        string[]? documentGrantTypes = null)
    {
        var authenticator = new Mock<IClientAuthenticator>();
        authenticator.Setup(a => a.ClientAuthenticationMethodsSupported).Returns(authenticationMethods ??
        [
            ClientAuthenticationMethods.None,
            ClientAuthenticationMethods.PrivateKeyJwt,
            ClientAuthenticationMethods.ClientSecretBasic,
        ]);

        var grants = new Mock<IGrantTypeInformer>();
        grants.Setup(g => g.GrantTypesSupported).Returns(grantTypes ??
        [
            GrantTypes.AuthorizationCode,
            GrantTypes.RefreshToken,
            GrantTypes.ClientCredentials,
            GrantTypes.Password,
            GrantTypes.JwtBearer,
            GrantTypes.DeviceAuthorization,
        ]);

        var builders = Array.ConvertAll(responseTypeParts ?? [ResponseTypes.Code], part =>
        {
            var builder = new Mock<IAuthorizationResponseBuilder>();
            builder.Setup(b => b.ResponseType).Returns(part);
            return builder.Object;
        });

        var options = new OidcOptions
        {
            NewClientOptions = new NewClientOptions { AllowedGrantTypes = allowedGrantTypes },
            ClientIdMetadataDocuments = { AllowedGrantTypes = documentGrantTypes },
        };
        return new ClientIdMetadataDocumentReader(
            authenticator.Object,
            [grants.Object],
            builders,
            Mock.Of<IOptionsMonitor<OidcOptions>>(monitor => monitor.CurrentValue == options),
            Mock.Of<IOptionsMonitor<SecureHttpFetchOptions>>(monitor => monitor.CurrentValue == new SecureHttpFetchOptions
            {
                AllowedDestinations = allowedDestinations,
            }));
    }

    private static JsonObject Document(string json = "{}")
    {
        var document = JsonNode.Parse(json)!.AsObject();
        document.TryAdd("client_id", ClientId);
        document.TryAdd("redirect_uris", new JsonArray("https://client.example.com/cb"));
        return document;
    }

    private static ClientRegistrationRequest Read(JsonObject document, ClientIdMetadataDocumentReader? reader = null)
    {
        var result = (reader ?? CreateReader()).Read(ClientId, document);
        Assert.True(result.TryGetSuccess(out var metadata), result.TryGetFailure(out var failure) ? failure.Reason : null);
        return metadata;
    }

    private static void Refused(JsonObject document, ClientIdMetadataDocumentReader? reader = null)
    {
        var result = (reader ?? CreateReader()).Read(ClientId, document);
        Assert.True(result.TryGetFailure(out var failure), "the document was expected to be refused");
        Assert.False(failure.MayPass);
    }

    /// <summary>
    /// The example document of the MCP authorization specification (revision 2026-07-28, "Example Metadata Document"):
    /// loopback redirect URIs and no application type.
    /// </summary>
    [Fact]
    public void TheMcpExampleDocument_IsReadAsANativePublicClient()
    {
        var document = JsonNode.Parse(
            """
            {
              "client_id": "https://client.example.com/metadata.json",
              "client_name": "Example MCP Client",
              "client_uri": "https://app.example.com",
              "logo_uri": "https://app.example.com/logo.png",
              "redirect_uris": [
                "http://127.0.0.1:3000/callback",
                "http://localhost:3000/callback"
              ],
              "grant_types": ["authorization_code"],
              "response_types": ["code"],
              "token_endpoint_auth_method": "none"
            }
            """)!.AsObject();

        var metadata = Read(document);

        Assert.Equal(ClientId, metadata.ClientId);
        Assert.Equal(ClientAuthenticationMethods.None, metadata.TokenEndpointAuthMethod);
        Assert.Equal(ApplicationTypes.Native, metadata.ApplicationType);
        Assert.Equal("Example MCP Client", metadata.ClientName);
    }

    [Theory]
    [InlineData("https://client.example.com/other.json")]
    [InlineData("https://client.example.com:443/metadata.json")]
    [InlineData("https://CLIENT.example.com/metadata.json")]
    public void ADocumentNamingAnotherClientId_IsRefused(string documentClientId)
        => Refused(Document($$"""{"client_id":"{{documentClientId}}"}"""));

    [Theory]
    [InlineData("""{"client_id":null}""")]
    [InlineData("""{"client_id":42}""")]
    public void ADocumentWithoutAClientIdString_IsRefused(string json)
        => Refused(Document(json));

    [Fact]
    public void ADocumentWithoutAClientId_IsRefused()
    {
        var document = Document();
        document.Remove("client_id");
        Refused(document);
    }

    /// <summary>
    /// Section 4.1: "the client_secret and client_secret_expires_at properties MUST NOT be used", "private key material
    /// MUST NOT be included", and "jwks_uri" and "jwks" "MUST NOT both be present".
    /// </summary>
    [Theory]
    [InlineData("""{"client_secret":"s3cret"}""")]
    [InlineData("""{"client_secret_expires_at":0}""")]
    [InlineData("""{"jwks_uri":"https://client.example.com/jwks","jwks":{"keys":[]}}""")]
    [InlineData("""{"jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"a","y":"b","d":"c"}]}}""")]
    [InlineData("""{"jwks":{"keys":[{"kty":"RSA","n":"a","e":"AQAB","p":"c"}]}}""")]
    [InlineData("""{"jwks":{"keys":[{"kty":"RSA","n":"a","e":"AQAB","oth":[]}]}}""")]
    [InlineData("""{"jwks":{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}}""")]
    public void ADocumentCarryingASecret_IsRefused(string json) => Refused(Document(json));

    /// <summary>
    /// Section 5: with neither member the server "MUST assume the token endpoint authentication method of none", and it
    /// "MUST NOT apply the default value of token_endpoint_auth_method defined in Section 2 of [RFC7591]".
    /// </summary>
    [Fact]
    public void ADocumentNamingNoMethod_IsAPublicClient()
        => Assert.Equal(ClientAuthenticationMethods.None, Read(Document()).TokenEndpointAuthMethod);

    /// <summary>
    /// Section 5.1: a client offering ["none", "private_key_jwt"] at a server supporting private_key_jwt "should use the
    /// private_key_jwt token endpoint authentication method".
    /// </summary>
    [Fact]
    public void AMethodProvingTheClient_IsChosenOverNone()
        => Assert.Equal(
            ClientAuthenticationMethods.PrivateKeyJwt,
            Read(Document(
                """{"token_endpoint_auth_methods_supported":["none","private_key_jwt"],"jwks_uri":"https://client.example.com/jwks"}"""))
                .TokenEndpointAuthMethod);

    [Fact]
    public void NoneIsChosen_WhenTheServerSupportsNothingElseOffered()
        => Assert.Equal(
            ClientAuthenticationMethods.None,
            Read(
                Document("""{"token_endpoint_auth_methods_supported":["none","private_key_jwt"]}"""),
                CreateReader(authenticationMethods: [ClientAuthenticationMethods.None])).TokenEndpointAuthMethod);

    [Fact]
    public void TheSingularMethod_IsReadWithoutTheList()
        => Assert.Equal(
            ClientAuthenticationMethods.PrivateKeyJwt,
            Read(Document("""{"token_endpoint_auth_method":"private_key_jwt"}""")).TokenEndpointAuthMethod);

    [Theory]
    // Section 5: the singular value "MUST be included within token_endpoint_auth_methods_supported"
    [InlineData("""{"token_endpoint_auth_methods_supported":["none"],"token_endpoint_auth_method":"private_key_jwt"}""")]
    // Section 4.1: no "method based around a shared symmetric secret", wherever it is declared
    [InlineData("""{"token_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic"]}""")]
    [InlineData("""{"token_endpoint_auth_method":"client_secret_post"}""")]
    [InlineData("""{"token_endpoint_auth_method":"client_secret_jwt"}""")]
    // Not what the members are
    [InlineData("""{"token_endpoint_auth_methods_supported":"none"}""")]
    [InlineData("""{"token_endpoint_auth_methods_supported":[1]}""")]
    [InlineData("""{"token_endpoint_auth_method":["none"]}""")]
    public void AMethodDeclarationBreakingARule_IsRefused(string json) => Refused(Document(json));

    /// <summary>
    /// Section 5: when the server "does not support any of the token endpoint authentication methods declared", it
    /// "MUST abort the authorization request and token requests with invalid_client".
    /// </summary>
    [Fact]
    public void ADocumentOfferingOnlyUnsupportedMethods_IsRefused()
        => Refused(
            Document("""{"token_endpoint_auth_methods_supported":["private_key_jwt"]}"""),
            CreateReader(authenticationMethods: [ClientAuthenticationMethods.None]));

    /// <summary>
    /// Section 6: the server "MUST filter the grant_types and response_types array-valued fields and find the
    /// intersection", and rejects the client when either is empty.
    /// </summary>
    [Fact]
    public void GrantAndResponseTypes_AreFilteredToWhatTheServerSupports()
    {
        var metadata = Read(Document(
            """{"grant_types":["authorization_code","urn:example:unknown","refresh_token"],"response_types":["code","code token"]}"""));

        Assert.Equal([GrantTypes.AuthorizationCode, GrantTypes.RefreshToken], metadata.GrantTypes);
        Assert.Equal([[ResponseTypes.Code]], metadata.ResponseTypes);
    }

    /// <summary>
    /// A grant type the host does not allow a new client is filtered out of a document as an unsupported one is,
    /// where a registration asking for it is refused.
    /// </summary>
    [Fact]
    public void AGrantTypeTheHostDoesNotAllow_IsFilteredOut()
        => Assert.Equal(
            [GrantTypes.AuthorizationCode],
            Read(
                Document("""{"grant_types":["authorization_code","refresh_token"]}"""),
                CreateReader(allowedGrantTypes: [GrantTypes.AuthorizationCode])).GrantTypes);

    /// <summary>
    /// A document is anybody's, so unless the host names others it gets only the grants an end user takes part in.
    /// </summary>
    [Fact]
    public void ByDefault_ADocumentKeepsOnlyTheGrantsAnEndUserTakesPartIn()
        => Assert.Equal(
            [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken],
            Read(Document("""{"grant_types":["authorization_code","client_credentials","refresh_token","urn:ietf:params:oauth:grant-type:device_code"]}""")).GrantTypes);

    [Fact]
    public void AGrantTheHostOpensToDocuments_IsKeptForAClientProvingItself()
        => Assert.Equal(
            [GrantTypes.AuthorizationCode, GrantTypes.ClientCredentials],
            Read(
                Document("""{"grant_types":["authorization_code","client_credentials"],"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://client.example.com/jwks"}"""),
                CreateReader(documentGrantTypes: [GrantTypes.AuthorizationCode, GrantTypes.ClientCredentials])).GrantTypes);

    /// <summary>
    /// RFC 6749 section 4.4: "The client credentials grant type MUST only be used by confidential clients", so a client
    /// authenticating with none loses it, and the password and JWT bearer grants, whatever the host opens.
    /// </summary>
    [Theory]
    [InlineData(GrantTypes.ClientCredentials)]
    [InlineData(GrantTypes.Password)]
    [InlineData(GrantTypes.JwtBearer)]
    public void AGrantForConfidentialClients_IsNeverKeptForAPublicOne(string grantType)
        => Assert.Equal(
            [GrantTypes.AuthorizationCode],
            Read(
                Document($$"""{"grant_types":["authorization_code","{{grantType}}"]}"""),
                CreateReader(documentGrantTypes: [GrantTypes.AuthorizationCode, grantType])).GrantTypes);

    [Fact]
    public void ADocumentOfOnlyGrantTypesTheHostDoesNotAllow_IsRefused()
        => Refused(
            Document("""{"grant_types":["refresh_token"],"response_types":[]}"""),
            CreateReader(allowedGrantTypes: [GrantTypes.AuthorizationCode]));

    /// <summary>
    /// A null where a type belongs names none, so it is dropped as an unsupported one is rather than failing the request.
    /// </summary>
    [Fact]
    public void ANullGrantOrResponseType_IsDropped()
    {
        var metadata = Read(Document("""{"grant_types":[null,"authorization_code"],"response_types":[null,"code"]}"""));

        Assert.Equal([GrantTypes.AuthorizationCode], metadata.GrantTypes);
        Assert.Equal([[ResponseTypes.Code]], metadata.ResponseTypes);
    }

    [Theory]
    [InlineData("""{"response_types":[null]}""")]
    [InlineData("""{"grant_types":["urn:example:unknown"]}""")]
    [InlineData("""{"response_types":["token"]}""")]
    public void ADocumentOfNoSupportedGrantOrResponseType_IsRefused(string json) => Refused(Document(json));

    [Fact]
    public void ADocumentDeclaringNoResponseType_IsKeptWithNone()
        => Assert.Empty(Read(Document("""{"grant_types":["refresh_token"],"response_types":[]}""")).ResponseTypes);

    [Theory]
    [InlineData("""["https://client.example.com/cb"]""", ApplicationTypes.Web)]
    [InlineData("""["http://127.0.0.1:3000/cb","com.example.app:/cb"]""", ApplicationTypes.Native)]
    [InlineData("""["http://[::1]/cb"]""", ApplicationTypes.Native)]
    [InlineData("""["https://client.example.com/cb","http://127.0.0.1/cb"]""", ApplicationTypes.Web)]
    [InlineData("""[]""", ApplicationTypes.Web)]
    public void ADocumentNamingNoApplicationType_IsTypedByItsRedirectUris(string redirectUris, string expected)
    {
        var document = Document();
        document["redirect_uris"] = JsonNode.Parse(redirectUris);

        Assert.Equal(expected, Read(document).ApplicationType);
    }

    /// <summary>
    /// Section 10.7: the server "SHOULD ensure they only fetch or parse URLs with known and supported URI schemes",
    /// naming "a URI scheme such as javascript:". A document is anybody's, and a response posted to a javascript
    /// redirect URI would run its author's script in this server's origin.
    /// </summary>
    [Theory]
    [InlineData("redirect_uris", """["javascript:alert(document.domain)//x"]""")]
    [InlineData("redirect_uris", """["data:text/html,x"]""")]
    [InlineData("redirect_uris", """["myapp:/cb"]""")]
    [InlineData("redirect_uris", """["http://client.example.com/cb"]""")]
    [InlineData("redirect_uris", """["cb"]""")]
    [InlineData("jwks_uri", "\"jwks\"")]
    [InlineData("sector_identifier_uri", "\"http://client.example.com/sector\"")]
    [InlineData("backchannel_client_notification_endpoint", "\"http://client.example.com/ciba\"")]
    [InlineData("post_logout_redirect_uris", """["javascript:alert(1)"]""")]
    [InlineData("frontchannel_logout_uri", "\"javascript:alert(1)\"")]
    [InlineData("backchannel_logout_uri", "\"http://client.example.com/logout\"")]
    [InlineData("client_uri", "\"javascript:alert(1)\"")]
    [InlineData("logo_uri", "\"data:image/png;base64,AA==\"")]
    [InlineData("policy_uri", "\"http://client.example.com/policy\"")]
    [InlineData("tos_uri", "\"javascript:alert(1)\"")]
    [InlineData("initiate_login_uri", "\"http://client.example.com/login\"")]
    [InlineData("jwks_uri", "\"http://client.example.com/jwks\"")]
    [InlineData("request_uris", """["http://client.example.com/request"]""")]
    public void AUriOfASchemeADocumentMayNotUse_IsRefused(string member, string value)
    {
        var document = Document();
        document[member] = JsonNode.Parse(value);
        Refused(document);
    }

    /// <summary>
    /// Section 10.7 asks the same of "any URLs contained within a Client ID Metadata Document" as of its own URL, so a
    /// URI the server fetches or posts to is refused when it is a destination the host opened for its own services.
    /// </summary>
    [Theory]
    [InlineData("jwks_uri", "\"https://internal.example.com/jwks\"")]
    [InlineData("sector_identifier_uri", "\"https://internal.example.com/sector\"")]
    [InlineData("backchannel_logout_uri", "\"https://internal.example.com/logout\"")]
    [InlineData("backchannel_client_notification_endpoint", "\"https://internal.example.com/ciba\"")]
    [InlineData("request_uris", """["https://internal.example.com/admin"]""")]
    public void AUriTheHostAllowsForItsServices_IsRefused(string member, string value)
    {
        var document = Document();
        document[member] = JsonNode.Parse(value);

        Assert.NotNull(Read(document));
        Refused(document, CreateReader(allowedDestinations: [new Uri("https://internal.example.com/")]));
    }

    [Theory]
    [InlineData("""["https://client.example.com/cb"]""")]
    [InlineData("""["http://127.0.0.1:3000/cb","http://localhost/cb","http://[::1]/cb"]""")]
    [InlineData("""["com.example.app:/cb"]""")]
    public void ARedirectUriOfAWebOrNativeClient_IsKept(string redirectUris)
    {
        var document = Document();
        document["redirect_uris"] = JsonNode.Parse(redirectUris);
        Assert.NotEmpty(Read(document).RedirectUris!);
    }

    [Theory]
    [InlineData("""{"pkce_required":false}""")]
    [InlineData("""{"pkce_required":false,"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://client.example.com/jwks"}""")]
    public void ADocumentTurningPkceOff_StillRequiresIt(string json)
        => Assert.True(Read(Document(json)).PkceRequired);

    [Fact]
    public void ANamedApplicationType_IsKept()
        => Assert.Equal(
            ApplicationTypes.Web,
            Read(Document("""{"application_type":"web","redirect_uris":["http://127.0.0.1/cb"]}""")).ApplicationType);

    [Fact]
    public void AMemberOfTheWrongShape_IsRefused()
        => Refused(Document("""{"redirect_uris":"https://client.example.com/cb"}"""));
}
