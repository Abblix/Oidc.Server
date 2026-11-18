// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Features.UriValidation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Options;
using Parameters = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// Reads a client's metadata document into the registration metadata the server judges a dynamically registered
/// client by, applying what draft-ietf-oauth-client-id-metadata-document asks beyond RFC 7591: the identifier the
/// document names, the credentials it must not carry, the authentication method the server picks and the grant and
/// response types it keeps.
/// </summary>
/// <param name="clientAuthenticator">Names the client authentication methods this server supports.</param>
/// <param name="grantTypeInformers">Name the grant types this server supports.</param>
/// <param name="responseBuilders">Name the response types this server supports.</param>
/// <param name="options">Holds the grant types the host allows a new client, read on each document.</param>
/// <param name="fetchOptions">Holds the destinations the host opened for its own services, read on each document.
/// </param>
internal sealed class ClientIdMetadataDocumentReader(
    IClientAuthenticator clientAuthenticator,
    IEnumerable<IGrantTypeInformer> grantTypeInformers,
    IEnumerable<IAuthorizationResponseBuilder> responseBuilders,
    IOptionsMonitor<OidcOptions> options,
    IOptionsMonitor<SecureHttpFetchOptions> fetchOptions)
{
    /// <summary>
    /// The methods built on a secret shared between client and server, which a public document cannot establish.
    /// </summary>
    private static readonly string[] SharedSecretMethods =
    [
        ClientAuthenticationMethods.ClientSecretBasic,
        ClientAuthenticationMethods.ClientSecretPost,
        ClientAuthenticationMethods.ClientSecretJwt,
    ];

    /// <summary>
    /// The members of a JSON Web Key that carry private or symmetric key material (RFC 7518 sections 6.2.2, 6.3.2 and
    /// 6.4.1).
    /// </summary>
    private static readonly string[] PrivateKeyMembers =
    [
        JsonWebKeyPropertyNames.PrivateExponent,
        JsonWebKeyPropertyNames.FirstPrimeFactor,
        JsonWebKeyPropertyNames.SecondPrimeFactor,
        JsonWebKeyPropertyNames.FirstFactorCrtExponent,
        JsonWebKeyPropertyNames.SecondFactorCrtExponent,
        JsonWebKeyPropertyNames.FirstCrtCoefficient,
        JsonWebKeyPropertyNames.KeyValue,
        JsonWebKeyPropertyNames.OtherPrimesInfo,
    ];

    /// <summary>
    /// The registration metadata <paramref name="document"/> describes the client <paramref name="clientId"/> with, or
    /// why it describes none.
    /// </summary>
    /// <param name="clientId">The client identifier URL the document was fetched from.</param>
    /// <param name="document">The document.</param>
    public Result<ClientRegistrationRequest, MetadataDocumentFailure> Read(string clientId, JsonObject document)
    {
        var refusal = WhyIdentifierRefused(clientId, document) ?? WhyCredentialsRefused(document);
        if (refusal is not null)
            return MetadataDocumentFailure.Terminal(refusal);

        return SelectAuthenticationMethod(document).Match(
            method => Deserialize(document).Match(
                metadata => Complete(clientId, document, metadata, method),
                failure => failure),
            failure => failure);
    }

    /// <summary>
    /// Section 4: the document "MUST contain a client_id property whose value MUST match the Client Identifier URL",
    /// compared "using simple string comparison".
    /// </summary>
    private static string? WhyIdentifierRefused(string clientId, JsonObject document)
        => TryReadString(document, Parameters.ClientId, out var documentClientId) &&
           string.Equals(documentClientId, clientId, StringComparison.Ordinal)
            ? null
            : "its client_id is not the URL it was fetched from";

    private static Result<ClientRegistrationRequest, MetadataDocumentFailure> Deserialize(JsonObject document)
    {
        try
        {
            return document.Deserialize<ClientRegistrationRequest>() is { } metadata
                ? metadata
                : MetadataDocumentFailure.Terminal("its metadata does not read");
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException or FormatException)
        {
            return MetadataDocumentFailure.Terminal($"its metadata does not read: {exception.Message}");
        }
    }

    private Result<ClientRegistrationRequest, MetadataDocumentFailure> Complete(
        string clientId,
        JsonObject document,
        ClientRegistrationRequest metadata,
        string authenticationMethod)
    {
        if (UriSchemes.WhyRefused(metadata, fetchOptions.CurrentValue.AllowedDestinations) is { } schemes)
            return MetadataDocumentFailure.Terminal(schemes);

        var grantTypes = SupportedGrantTypes(metadata.GrantTypes);
        var responseTypes = SupportedResponseTypes(metadata.ResponseTypes);

        // Section 6: the server "MUST filter the grant_types and response_types array-valued fields and find the
        // intersection of what the Client ID Metadata Document declares and what the Authorization Servers supports.
        // If the intersection of either of these two properties is empty, the Authorization Server MUST reject the
        // request with invalid_client". An empty response_types declares a client that uses no authorization endpoint,
        // and it is kept as it is
        if (grantTypes.Length == 0)
            return MetadataDocumentFailure.Terminal("this server supports none of its grant types");

        if (responseTypes.Length == 0 && metadata.ResponseTypes.Length > 0)
            return MetadataDocumentFailure.Terminal("this server supports none of its response types");

        return metadata with
        {
            ClientId = clientId,
            TokenEndpointAuthMethod = authenticationMethod,
            GrantTypes = grantTypes,
            ResponseTypes = responseTypes,
            ApplicationType = document.ContainsKey(Parameters.ApplicationType)
                ? metadata.ApplicationType
                : ApplicationTypeOf(metadata.RedirectUris),
        };
    }

    /// <summary>
    /// Why the document carries credentials a public document must not, section 4.1.
    /// </summary>
    private static string? WhyCredentialsRefused(JsonObject document)
    {
        // "the client_secret and client_secret_expires_at properties MUST NOT be used"
        if (document.ContainsKey(Parameters.ClientSecret) || document.ContainsKey(ResponseParameters.ClientSecretExpiresAt))
            return "it carries a client secret";

        // "The "jwks_uri" and "jwks" parameters MUST NOT both be present in the same request or response"
        if (document.ContainsKey(Parameters.Jwks) && document.ContainsKey(Parameters.JwksUri))
            return "it carries both jwks and jwks_uri";

        // "private key material MUST NOT be included in the Client ID Metadata Document; only public keys, such as those
        // published via the jwks or jwks_uri properties, are permitted". A symmetric key is a shared secret in the open
        if (document[Parameters.Jwks] is JsonObject jwks &&
            jwks[JsonWebKeySet.KeysMember] is JsonArray keys &&
            keys.OfType<JsonObject>().Any(key => PrivateKeyMembers.Any(key.ContainsKey)))
        {
            return "its jwks carries private or symmetric key material";
        }

        return null;
    }

    /// <summary>
    /// The client authentication methods the document declares, section 5.
    /// </summary>
    private static Result<string[], MetadataDocumentFailure> DeclaredAuthenticationMethods(JsonObject document)
    {
        if (!TryReadStrings(document, Parameters.TokenEndpointAuthMethodsSupported, out var list))
        {
            return MetadataDocumentFailure.Terminal(
                $"its {Parameters.TokenEndpointAuthMethodsSupported} is not a list of strings");
        }

        if (!TryReadString(document, Parameters.TokenEndpointAuthMethod, out var single))
            return MetadataDocumentFailure.Terminal($"its {Parameters.TokenEndpointAuthMethod} is not a string");

        // "If the client presents both ... the value in token_endpoint_auth_method MUST be included within
        // token_endpoint_auth_methods_supported"
        if (list is not null && single is not null && !list.Contains(single, StringComparer.Ordinal))
        {
            return MetadataDocumentFailure.Terminal(
                $"its {Parameters.TokenEndpointAuthMethod} is not among its {Parameters.TokenEndpointAuthMethodsSupported}");
        }

        // "When a Client ID Metadata Document contains neither ... the authorization server MUST assume the token
        // endpoint authentication method of none", and it "MUST NOT apply the default value of
        // token_endpoint_auth_method defined in Section 2 of [RFC7591]". The singular member is read only without the
        // list, which section 5 allows ("an authorization server MAY read the singular token_endpoint_auth_method")
        if (list is not null)
            return list;

        return single is not null ? new[] { single } : new[] { ClientAuthenticationMethods.None };
    }

    /// <summary>
    /// The client authentication method the client is held to, section 5.
    /// </summary>
    private Result<string, MetadataDocumentFailure> SelectAuthenticationMethod(JsonObject document)
        => DeclaredAuthenticationMethods(document).Match(Select, failure => failure);

    private Result<string, MetadataDocumentFailure> Select(string[] declared)
    {
        // Section 4.1: these "MUST NOT include client_secret_post, client_secret_basic, client_secret_jwt, or any other
        // method based around a shared symmetric secret"
        if (declared.FirstOrDefault(method => SharedSecretMethods.Contains(method, StringComparer.Ordinal)) is { } secret)
            return MetadataDocumentFailure.Terminal($"it declares {secret}, a method built on a shared secret");

        var supported = clientAuthenticator.ClientAuthenticationMethodsSupported.ToHashSet(StringComparer.Ordinal);

        // Section 5 has the server "select one of the values ... that it supports", and section 5.1 shows the choice:
        // a client declaring ["none", "private_key_jwt"] at a server supporting private_key_jwt "should use the
        // private_key_jwt token endpoint authentication method". So a method proving the client is chosen over none,
        // and none only when nothing else is supported
        var chosen = declared.FirstOrDefault(method => method != ClientAuthenticationMethods.None && supported.Contains(method))
                     ?? declared.FirstOrDefault(method => method == ClientAuthenticationMethods.None && supported.Contains(method));

        // "When an authorization server does not support any of the token endpoint authentication methods declared in
        // the Client ID Metadata Document, the authorization server MUST abort the authorization request and token
        // requests with invalid_client"
        if (chosen is null)
            return MetadataDocumentFailure.Terminal("this server supports none of its client authentication methods");

        return chosen;
    }

    /// <summary>
    /// The grant types of <paramref name="declared"/> this server supports and the host allows a new client.
    /// </summary>
    /// <remarks>
    /// A registration asking for a grant type outside <see cref="NewClientOptions.AllowedGrantTypes"/> is refused, but
    /// a document is filtered: section 6 has the server keep "the intersection of what the Client ID Metadata Document
    /// declares and what the Authorization Servers supports", and what the host allows is what it supports for such a
    /// client, so one document can serve servers allowing different grant types.
    /// </remarks>
    private string[] SupportedGrantTypes(string[] declared)
    {
        var supported = grantTypeInformers
            .SelectMany(informer => informer.GrantTypesSupported)
            .ToHashSet(StringComparer.Ordinal);

        if (options.CurrentValue.NewClientOptions.AllowedGrantTypes is { } allowed)
            supported.IntersectWith(allowed);

        return declared.Where(supported.Contains).Distinct(StringComparer.Ordinal).ToArray();
    }

    private string[][] SupportedResponseTypes(string[][] declared)
    {
        var supportedParts = responseBuilders
            .Select(builder => builder.ResponseType)
            .ToHashSet(StringComparer.Ordinal);

        // A combination is supported when every part of it is; an empty one names nothing and is left for the
        // registration checks to refuse
        return declared.Where(combination => combination.All(supportedParts.Contains)).ToArray();
    }

    /// <summary>
    /// The application type of a document that names none.
    /// </summary>
    /// <remarks>
    /// The draft defines no application type, and the default OpenID Connect Dynamic Client Registration 1.0 section 2
    /// gives one omitted, <c>web</c>, refuses the loopback redirect URIs of a client running on the user's own machine:
    /// the MCP authorization specification's own example document lists <c>http://127.0.0.1:3000/callback</c> and
    /// <c>http://localhost:3000/callback</c> and names no application type. So a document naming none is a native
    /// client when every redirect URI it lists is a loopback <c>http</c> URI or uses a scheme of its own, as RFC 9700
    /// section 2.6 allows the <c>http</c> scheme only "for native clients that use loopback interface redirection", and
    /// a web client otherwise, judged by the same checks a registration naming its type is.
    /// </remarks>
    private static string ApplicationTypeOf(Uri[]? redirectUris)
        => redirectUris is { Length: > 0 } && redirectUris.All(IsNativeRedirect)
            ? ApplicationTypes.Native
            : ApplicationTypes.Web;

    private static bool IsNativeRedirect(Uri uri)
        => uri is { IsAbsoluteUri: true } &&
           (uri.Scheme == Uri.UriSchemeHttp
               ? LoopbackHosts.IsNativeLoopbackHost(uri)
               : uri.Scheme != Uri.UriSchemeHttps);

    private static bool TryReadString(JsonObject document, string member, out string? value)
    {
        value = null;
        switch (document[member])
        {
            case null:
                return true;

            case JsonValue node when node.GetValueKind() == JsonValueKind.String:
                value = node.GetValue<string>();
                return true;

            default:
                return false;
        }
    }

    private static bool TryReadStrings(JsonObject document, string member, out string[]? values)
    {
        values = null;
        switch (document[member])
        {
            case null:
                return true;

            case JsonArray array when array.All(item => item?.GetValueKind() == JsonValueKind.String):
                values = array.Select(item => item!.GetValue<string>()).ToArray();
                return true;

            default:
                return false;
        }
    }
}
