// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Model;
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
        string[]? responseTypeParts = null)
    {
        var authenticator = new Mock<IClientAuthenticator>();
        authenticator.Setup(a => a.ClientAuthenticationMethodsSupported).Returns(authenticationMethods ??
        [
            ClientAuthenticationMethods.None,
            ClientAuthenticationMethods.PrivateKeyJwt,
            ClientAuthenticationMethods.ClientSecretBasic,
        ]);

        var grants = new Mock<IGrantTypeInformer>();
        grants.Setup(g => g.GrantTypesSupported)
            .Returns(grantTypes ?? [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken]);

        var builders = Array.ConvertAll(responseTypeParts ?? [ResponseTypes.Code], part =>
        {
            var builder = new Mock<IAuthorizationResponseBuilder>();
            builder.Setup(b => b.ResponseType).Returns(part);
            return builder.Object;
        });

        return new ClientIdMetadataDocumentReader(authenticator.Object, [grants.Object], builders);
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

    [Theory]
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
    [InlineData("""["http://client.example.com/cb"]""", ApplicationTypes.Web)]
    [InlineData("""[]""", ApplicationTypes.Web)]
    public void ADocumentNamingNoApplicationType_IsTypedByItsRedirectUris(string redirectUris, string expected)
    {
        var document = Document();
        document["redirect_uris"] = JsonNode.Parse(redirectUris);

        Assert.Equal(expected, Read(document).ApplicationType);
    }

    [Fact]
    public void ANamedApplicationType_IsKept()
        => Assert.Equal(
            ApplicationTypes.Web,
            Read(Document("""{"application_type":"web","redirect_uris":["http://127.0.0.1/cb"]}""")).ApplicationType);

    [Fact]
    public void AMemberOfTheWrongShape_IsRefused()
        => Refused(Document("""{"redirect_uris":"https://client.example.com/cb"}"""));
}
