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

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Utils;
using Abblix.Utils.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using EndpointResponse = Abblix.Oidc.Server.Endpoints.Configuration.Interfaces.ConfigurationResponse;
using ModelResponse = Abblix.Oidc.Server.Model.ConfigurationResponse;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Builds the OpenID Connect discovery document by enriching the core metadata with endpoint URLs resolved from the
/// configured route templates and the current request's base URL, then returns it as a JSON <see cref="IResult"/>.
/// </summary>
public class ConfigurationResultFormatter(
    IOptionsSnapshot<OidcOptions> options,
    IOptions<OidcRouteOptions> routes,
    IHttpContextAccessor httpContextAccessor,
    IJsonWebTokenCreator jwtCreator,
    IAuthServiceKeysProvider serviceKeysProvider,
    TimeProvider clock) : IConfigurationResultFormatter
{
    /// <summary>
    /// Serializes the metadata into the <c>signed_metadata</c> JWS payload with the same null-omission semantics the
    /// wire JSON uses. Without re-attaching the modifier here the signed copy would carry <c>"field": null</c> entries
    /// the plain JSON omits, and RFC 8414 §2.1 "signed values take precedence" would then assert those nulls onto
    /// clients.
    /// </summary>
    private static readonly JsonSerializerOptions SignedMetadataSerializerOptions = new()
    {
        TypeInfoResolver = new DefaultJsonTypeInfoResolver().WithAddedModifier(JsonIgnoreNullsModifier.Apply),
    };

    /// <inheritdoc />
    public async Task<IResult> FormatResponseAsync(EndpointResponse response)
    {
        var routeOptions = routes.Value;

        var tokenEndpoint = Resolve(routeOptions.Token, OidcEndpoints.Token);
        var revocationEndpoint = Resolve(routeOptions.Revocation, OidcEndpoints.Revocation);
        var introspectionEndpoint = Resolve(routeOptions.Introspection, OidcEndpoints.Introspection);
        var userInfoEndpoint = Resolve(routeOptions.UserInfo, OidcEndpoints.UserInfo);

        var modelResponse = new ModelResponse
        {
            Issuer = response.Issuer,

            JwksUri = Resolve(routeOptions.Keys, OidcEndpoints.Keys),

            AuthorizationEndpoint = Resolve(routeOptions.Authorize, OidcEndpoints.Authorize),
            UserInfoEndpoint = userInfoEndpoint,
            EndSessionEndpoint = Resolve(routeOptions.EndSession, OidcEndpoints.EndSession),
            CheckSessionIframe = Resolve(routeOptions.CheckSession, OidcEndpoints.CheckSession),
            PushedAuthorizationRequestEndpoint = Resolve(routeOptions.PushedAuthorizationRequest, OidcEndpoints.PushedAuthorizationRequest),

            TokenEndpoint = tokenEndpoint,
            RevocationEndpoint = revocationEndpoint,
            IntrospectionEndpoint = introspectionEndpoint,

            RegistrationEndpoint = Resolve(routeOptions.Register, OidcEndpoints.RegisterClient),

            BackChannelAuthenticationEndpoint = Resolve(routeOptions.BackChannelAuthentication, OidcEndpoints.BackChannelAuthentication),

            DeviceAuthorizationEndpoint = Resolve(routeOptions.DeviceAuthorization, OidcEndpoints.DeviceAuthorization),

            FrontChannelLogoutSupported = response.FrontChannelLogoutSupported,
            FrontChannelLogoutSessionSupported = response.FrontChannelLogoutSessionSupported,
            BackChannelLogoutSupported = response.BackChannelLogoutSupported,
            BackChannelLogoutSessionSupported = response.BackChannelLogoutSessionSupported,

            ClaimsParameterSupported = response.ClaimsParameterSupported,

            ScopesSupported = response.ScopesSupported,
            ClaimsSupported = response.ClaimsSupported,

            GrantTypesSupported = response.GrantTypesSupported,
            ResponseTypesSupported = response.ResponseTypesSupported,
            ResponseModesSupported = response.ResponseModesSupported,

            TokenEndpointAuthMethodsSupported = response.TokenEndpointAuthMethodsSupported,
            TokenEndpointAuthSigningAlgValuesSupported = response.TokenEndpointAuthSigningAlgValuesSupported,
            TlsClientCertificateBoundAccessTokens = response.TlsClientCertificateBoundAccessTokens,

            IdTokenSigningAlgValuesSupported = response.IdTokenSigningAlgValuesSupported,
            SubjectTypesSupported = response.SubjectTypesSupported,
            CodeChallengeMethodsSupported = response.CodeChallengeMethodsSupported,
            PromptValuesSupported = response.PromptValuesSupported,

            RequestParameterSupported = response.RequestParameterSupported,
            RequestObjectSigningAlgValuesSupported = response.RequestObjectSigningAlgValuesSupported,
            RequestObjectEncryptionAlgValuesSupported = response.RequestObjectEncryptionAlgValuesSupported,
            RequestObjectEncryptionEncValuesSupported = response.RequestObjectEncryptionEncValuesSupported,
            AuthorizationSigningAlgValuesSupported = response.AuthorizationSigningAlgValuesSupported,
            AuthorizationEncryptionAlgValuesSupported = response.AuthorizationEncryptionAlgValuesSupported,
            AuthorizationEncryptionEncValuesSupported = response.AuthorizationEncryptionEncValuesSupported,

            IntrospectionSigningAlgValuesSupported = response.IntrospectionSigningAlgValuesSupported,
            IntrospectionEncryptionAlgValuesSupported = response.IntrospectionEncryptionAlgValuesSupported,
            IntrospectionEncryptionEncValuesSupported = response.IntrospectionEncryptionEncValuesSupported,

            RequirePushedAuthorizationRequests = response.RequirePushedAuthorizationRequests,
            RequireSignedRequestObject = response.RequireSignedRequestObject,

            UserInfoSigningAlgValuesSupported = response.UserInfoSigningAlgValuesSupported,
            DpopSigningAlgValuesSupported = response.DpopSigningAlgValuesSupported,

            BackChannelTokenDeliveryModesSupported = response.BackChannelTokenDeliveryModesSupported,
            BackChannelAuthenticationRequestSigningAlgValuesSupported = response.BackChannelAuthenticationRequestSigningAlgValuesSupported,
            BackChannelUserCodeParameterSupported = response.BackChannelUserCodeParameterSupported,

            AcrValuesSupported = response.AcrValuesSupported,

            AuthorizationResponseIssParameterSupported = response.AuthorizationResponseIssParameterSupported,

            AuthorizationDetailsTypesSupported = response.AuthorizationDetailsTypesSupported,
        };

        var mtlsOptions = options.Value.Discovery.MtlsEndpointAliases;
        var mtlsBaseUri = options.Value.Discovery.MtlsBaseUri;

        if (mtlsOptions != null || mtlsBaseUri != null)
        {
            modelResponse = modelResponse with
            {
                MtlsEndpointAliases = new Abblix.Oidc.Server.Model.MtlsAliases
                {
                    TokenEndpoint = mtlsOptions?.TokenEndpoint ?? Rebase(tokenEndpoint, mtlsBaseUri),
                    RevocationEndpoint = mtlsOptions?.RevocationEndpoint ?? Rebase(revocationEndpoint, mtlsBaseUri),
                    IntrospectionEndpoint = mtlsOptions?.IntrospectionEndpoint ?? Rebase(introspectionEndpoint, mtlsBaseUri),
                    UserInfoEndpoint = mtlsOptions?.UserInfoEndpoint ?? Rebase(userInfoEndpoint, mtlsBaseUri),
                }
            };
        }

        if (options.Value.Discovery.SignedMetadata)
        {
            modelResponse = modelResponse with { SignedMetadata = await SignAsync(modelResponse) };
        }

        return Results.Json(modelResponse);
    }

    /// <summary>
    /// Produces the RFC 8414 §2.1 <c>signed_metadata</c> value: a compact JWS whose payload restates the supplied
    /// metadata plus a mandatory <c>iss</c> claim. The result is always a pure JWS, so a deployment that also issues
    /// JWE access tokens does not turn this into a JWE the client cannot verify against <c>jwks_uri</c>.
    /// </summary>
    private async Task<string> SignAsync(ModelResponse metadata)
    {
        var signingKey = await serviceKeysProvider.GetSigningKeys(true).FirstOrDefaultAsync();
        if (signingKey is null)
        {
            throw new InvalidOperationException(
                $"{nameof(DiscoveryOptions)}.{nameof(DiscoveryOptions.SignedMetadata)} is enabled but no signing keys are configured. " +
                "Configure signing certificates so the discovery document can be signed (RFC 8414 §2.1).");
        }

        // Serialized before signed_metadata is set on the outer object, so the signed payload never contains
        // signed_metadata itself (RFC 8414 §2.1).
        var payload = JsonSerializer.SerializeToNode(metadata, SignedMetadataSerializerOptions) switch
        {
            JsonObject jsonObject => jsonObject,

            _ => throw new InvalidOperationException(
                "Discovery metadata serialized to a non-object JSON node. The metadata must serialize to a JSON object so it " +
                "can form the signed_metadata JWS payload (RFC 8414 §2.1); " +
                "a different node kind indicates a broken serializer or type-info resolver."),
        };

        var token = new JsonWebToken
        {
            Header = { Algorithm = signingKey.Algorithm },
            Payload = new JsonWebTokenPayload(payload)
            {
                Issuer = metadata.Issuer,
                IssuedAt = clock.GetUtcNow(),
            },
        };

        return await jwtCreator.IssueAsync(token, signingKey);
    }

    /// <summary>
    /// Resolves the absolute URL for an endpoint route if endpoint path discovery is enabled and the endpoint is
    /// active. Combines the request's base URL (scheme, host, base path) with the configured route template.
    /// </summary>
    private Uri? Resolve(string routePath, OidcEndpoints enablingFlag)
    {
        if (!options.Value.Discovery.AllowEndpointPathsDiscovery ||
            !options.Value.EnabledEndpoints.HasFlag(enablingFlag))
            return null;

        var request = httpContextAccessor.HttpContext.NotNull(nameof(HttpContext)).Request;
        return new Uri(request.GetAppUrl() + routePath, UriKind.Absolute);
    }

    /// <summary>
    /// Rebases an original URI onto a different base URI, preserving the original's path. Used to generate mTLS
    /// endpoint aliases with an alternative base URL.
    /// </summary>
    private static Uri? Rebase(Uri? original, Uri? baseUri)
    {
        if (baseUri == null)
            return original;

        if (original == null)
            return null;

        var basePath = baseUri.AbsolutePath.TrimEnd('/');
        var origPath = original.AbsolutePath.TrimStart('/');

        var ub = new System.UriBuilder(baseUri)
        {
            Path = string.IsNullOrEmpty(basePath) || basePath == "/"
                ? $"/{origPath}"
                : $"{basePath}/{origPath}",
        };
        return ub.Uri;
    }
}
