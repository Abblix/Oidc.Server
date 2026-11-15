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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.MinimalApi.Conformance.TestHost;

/// <summary>
/// One family of FAPI or CIBA plans: the security profile its clients are held to, and the static clients of each
/// configuration its plans are run with.
/// </summary>
/// <remarks>
/// Each client names its profile for itself, since every family is served by the host's one tenant: the server
/// without a license serves a single issuer, and a tenant per family, each with the profile as its floor, would need
/// one naming them all.
/// </remarks>
/// <param name="Profile">The security profile the family's clients are held to.</param>
/// <param name="Scope">The scope the suite requests for the family's clients.</param>
/// <param name="Plans">The configurations the family's plans are run with, two clients each.</param>
/// <param name="Configure">What the profile asks of a client beyond its credentials and token binding.</param>
public sealed record FapiPlanFamily(
    ClientSecurityProfile Profile,
    string Scope,
    SuitePlan[] Plans,
    Action<ClientInfo, SuitePlan, Uri> Configure)
{
    /// <summary>
    /// The FAPI 2.0 Security Profile, with every combination of client authentication and token binding its plan
    /// variants name. The suite writes the issuer as the client assertion audience under FAPI 2.0, which is all
    /// section 5.3.2.1 lets the server accept, so the clients keep the default.
    /// </summary>
    public static FapiPlanFamily Fapi2SecurityProfile { get; } = new(
        ClientSecurityProfile.Fapi2,
        "openid profile offline_access",
        EveryClientAuthenticationAndBinding("abblix-fapi2"),
        (client, _, _) => client.AllowedResponseTypes = [[ResponseTypes.Code]]);

    /// <summary>
    /// FAPI 2.0 Message Signing: the Security Profile with signed request objects and signed authorization responses.
    /// </summary>
    public static FapiPlanFamily Fapi2MessageSigning { get; } = new(
        ClientSecurityProfile.Fapi2MessageSigning,
        "openid profile offline_access",
        EveryClientAuthenticationAndBinding("abblix-fapi2-ms"),
        (client, _, _) =>
        {
            client.AllowedResponseTypes = [[ResponseTypes.Code]];
            client.RequestObjectSigningAlgorithm = SigningAlgorithms.PS256;
        });

    /// <summary>
    /// FAPI 1.0 Advanced, whose tokens are always bound to the client certificate (Part 2 section 5.2.2).
    /// </summary>
    /// <remarks>
    /// The plan's client assertions name the token endpoint, one of its modules names the pushed authorization request
    /// endpoint at that endpoint, as RFC 9126 section 2 had the server accept before RFC 10070 section 5 replaced it,
    /// and another sends an array holding the issuer beside another value, which RFC 7523 section 3 allowed before RFC
    /// 10070 section 4 closed it. The server refuses all three by default, and the private key JWT clients are granted
    /// them, as a host grants a client written to the replaced texts that cannot change yet.
    /// </remarks>
    public static FapiPlanFamily Fapi1Advanced { get; } = new(
        ClientSecurityProfile.Fapi1Advanced,
        "openid profile offline_access",
        [
            new SuitePlan("abblix-fapi1-pkjwt", AuthenticatesByMutualTls: false, BindsTokensByMutualTls: true),
            new SuitePlan("abblix-fapi1-mtls", AuthenticatesByMutualTls: true, BindsTokensByMutualTls: true),
        ],
        (client, plan, _) =>
        {
            // code id_token for the plain response variant, code alone with the jwt response mode for the JARM one
            client.AllowedResponseTypes = [[ResponseTypes.Code, ResponseTypes.IdToken], [ResponseTypes.Code]];
            client.RequestObjectSigningAlgorithm = SigningAlgorithms.PS256;
            client.ClientAssertionAudiences = ClientAssertionAudiences.Issuer |
                                              ClientAssertionAudiences.TokenEndpoint |
                                              ClientAssertionAudiences.PushedAuthorizationRequestEndpoint;
            if (!plan.AuthenticatesByMutualTls)
                client.ClientAssertionAudiences |= ClientAssertionAudiences.AllowArray;

            // Part 2 section 5.2.2 asks PKCE only of a pushed request, which the profile enforces by itself
            client.PkceRequired = false;
        });

    /// <summary>
    /// FAPI-CIBA, which builds on FAPI 1.0 Advanced, in both delivery modes its plan runs.
    /// </summary>
    /// <remarks>
    /// The suite's client assertion at the backchannel authentication endpoint names that endpoint, and at the token
    /// endpoint the token endpoint, as CIBA Core 1.0 section 7.1 has the server accept: "the OP MUST accept its Issuer
    /// Identifier, Token Endpoint URL, or Backchannel Authentication Endpoint URL as values that identify it as an
    /// intended audience". RFC 10070 section 4 refuses both for every other client, so the host grants them to these.
    /// </remarks>
    public static FapiPlanFamily Ciba { get; } = new(
        ClientSecurityProfile.Fapi1Advanced,
        "openid profile offline_access",
        [
            new SuitePlan("abblix-ciba-pkjwt-poll", false, true, BackchannelTokenDeliveryModes.Poll),
            new SuitePlan("abblix-ciba-pkjwt-ping", false, true, BackchannelTokenDeliveryModes.Ping),
            new SuitePlan("abblix-ciba-mtls-poll", true, true, BackchannelTokenDeliveryModes.Poll),
            new SuitePlan("abblix-ciba-mtls-ping", true, true, BackchannelTokenDeliveryModes.Ping),
        ],
        (client, plan, suite) =>
        {
            client.AllowedResponseTypes = [];
            client.RedirectUris = [];
            client.AllowedGrantTypes = [GrantTypes.Ciba, GrantTypes.RefreshToken];
            client.BackChannelTokenDeliveryMode = plan.CibaDeliveryMode;
            if (plan.CibaDeliveryMode == BackchannelTokenDeliveryModes.Ping)
                client.BackChannelClientNotificationEndpoint = SuiteAddress(suite, plan, "ciba-notification-endpoint");
            client.BackChannelAuthenticationRequestSigningAlg = SigningAlgorithms.PS256;
            client.ClientAssertionAudiences = ClientAssertionAudiences.Issuer |
                                              ClientAssertionAudiences.TokenEndpoint |
                                              ClientAssertionAudiences.BackChannelAuthenticationEndpoint;
            client.PkceRequired = false;
        });

    /// <summary>
    /// Every family of FAPI and CIBA plans the host serves.
    /// </summary>
    public static FapiPlanFamily[] All { get; } = [Fapi2SecurityProfile, Fapi2MessageSigning, Fapi1Advanced, Ciba];

    /// <summary>
    /// The path a CIBA request is approved or denied at, standing in for the end user's device: the suite calls it
    /// with the request and the end user's answer (<c>automated_ciba_approval_url</c>).
    /// </summary>
    public const string CibaApprovalPath = "/conformance/ciba-approval";

    /// <summary>
    /// Mints the credentials of every client of the family, and returns the clients beside the configuration file the
    /// suite runs each plan with, keyed by the plan's alias.
    /// </summary>
    /// <param name="issuer">The issuer the clients are registered with.</param>
    /// <param name="mtlsBase">The address the issuer's mutual-TLS endpoint aliases are served at.</param>
    /// <param name="suite">The suite's base URL, which the clients' redirect and notification endpoints are on.</param>
    /// <param name="loginHint">The end user a CIBA request names.</param>
    public (IReadOnlyList<ClientInfo> Clients, IReadOnlyDictionary<string, JsonObject> PlanConfigurations) Declare(
        Uri issuer, Uri mtlsBase, Uri suite, string loginHint)
    {
        var clients = new List<ClientInfo>();
        var configurations = new Dictionary<string, JsonObject>();

        foreach (var plan in Plans)
        {
            var pair = new[] { 1, 2 }
                .Select(number => $"{plan.Alias}-{number}")
                .Select(clientId => (
                    Client: ClientOf(clientId, plan, suite),
                    Credentials: ClientCredentials.Create(clientId, SigningAlgorithms.PS256)))
                .ToArray();

            foreach (var (client, credentials) in pair)
            {
                client.Jwks = new JsonWebKeySet([credentials.PublicKey]);
                clients.Add(client);
            }

            configurations[plan.Alias] = SuiteConfiguration(plan, issuer, mtlsBase, loginHint, pair);
        }

        return (clients, configurations);
    }

    private ClientInfo ClientOf(string clientId, SuitePlan plan, Uri suite)
    {
        var callback = SuiteAddress(suite, plan, "callback");
        var client = new ClientInfo(clientId)
        {
            SecurityProfile = Profile,
            TokenEndpointAuthMethod = plan.AuthenticatesByMutualTls
                ? ClientAuthenticationMethods.SelfSignedTlsClientAuth
                : ClientAuthenticationMethods.PrivateKeyJwt,
            TokenEndpointAuthSigningAlgorithm = plan.AuthenticatesByMutualTls ? null : SigningAlgorithms.PS256,
            TlsClientCertificateBoundAccessTokens = plan.BindsTokensByMutualTls,
            RequireDPoP = !plan.BindsTokensByMutualTls,

            // Each one stated, since the defaults are RS256, which no FAPI profile admits
            IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
            AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,

            // The suite's second client sends its redirect URI with a query the client is told to register
            RedirectUris = [callback, new Uri(callback + "?dummy1=lorem&dummy2=ipsum")],
            AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken],
            OfflineAccess = OfflineAccess.Allowed,
        };
        Configure(client, plan, suite);
        return client;
    }

    private static Uri SuiteAddress(Uri suite, SuitePlan plan, string endpoint)
        => new(suite, $"/test/a/{plan.Alias}/{endpoint}");

    private JsonObject SuiteConfiguration(
        SuitePlan plan,
        Uri issuer,
        Uri mtlsBase,
        string loginHint,
        (ClientInfo Client, ClientCredentials Credentials)[] pair)
    {
        // The suite calls the resource with the access token: on the mutual-TLS alias when the token is bound to the
        // client certificate, which reaches the server only there
        var resourceBase = plan.BindsTokensByMutualTls ? mtlsBase : issuer;
        var configuration = new JsonObject
        {
            ["alias"] = plan.Alias,
            ["description"] = $"Abblix OIDC Server conformance host, {plan.Alias}",
            ["server"] = new JsonObject { ["discoveryUrl"] = new Uri(issuer, ".well-known/openid-configuration").AbsoluteUri },
            ["client"] = SuiteClient(plan, pair[0], loginHint),
            ["client2"] = SuiteClient(plan, pair[1], loginHint),
            ["mtls"] = SuiteCertificate(pair[0].Credentials),
            ["mtls2"] = SuiteCertificate(pair[1].Credentials),
            ["resource"] = new JsonObject { ["resourceUrl"] = new Uri(resourceBase, "connect/userinfo").AbsoluteUri },
        };

        if (plan.CibaDeliveryMode != null)
        {
            configuration["automated_ciba_approval_url"] =
                new Uri(issuer, CibaApprovalPath).AbsoluteUri + "?auth_req_id={auth_req_id}&action={action}";
        }

        return configuration;
    }

    private JsonObject SuiteClient(SuitePlan plan, (ClientInfo Client, ClientCredentials Credentials) member, string loginHint)
    {
        var client = new JsonObject
        {
            ["client_id"] = member.Client.ClientId,
            ["scope"] = Scope,
            ["jwks"] = JsonSerializer.SerializeToNode(new JsonWebKeySet([member.Credentials.PrivateKey])),
        };

        if (!plan.BindsTokensByMutualTls)
            client["dpop_signing_alg"] = SigningAlgorithms.PS256;

        if (plan.CibaDeliveryMode != null)
        {
            client["hint_type"] = "login_hint";
            client["hint_value"] = loginHint;
        }

        return client;
    }

    private static JsonObject SuiteCertificate(ClientCredentials credentials) => new()
    {
        ["key"] = credentials.PrivateKeyPem,
        ["cert"] = credentials.CertificatePem,
        ["ca"] = credentials.CertificatePem,
    };

    private static SuitePlan[] EveryClientAuthenticationAndBinding(string prefix) =>
    [
        new($"{prefix}-pkjwt-dpop", AuthenticatesByMutualTls: false, BindsTokensByMutualTls: false),
        new($"{prefix}-pkjwt-mtls", AuthenticatesByMutualTls: false, BindsTokensByMutualTls: true),
        new($"{prefix}-mtls-dpop", AuthenticatesByMutualTls: true, BindsTokensByMutualTls: false),
        new($"{prefix}-mtls-mtls", AuthenticatesByMutualTls: true, BindsTokensByMutualTls: true),
    ];
}
