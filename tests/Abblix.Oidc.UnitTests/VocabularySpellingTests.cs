// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Xunit;

namespace Abblix.Oidc.UnitTests;

/// <summary>
/// The server writes these values and every other test reads them through the same constants, so a mistyped value
/// would pass the whole suite while every client stopped understanding it. These tables write each value a second
/// time, apart from its constant, which is why they are literals here and nowhere else. A constant added to a class
/// without a row here fails its table, so a new value is spelled twice from the start.
/// </summary>
public class VocabularySpellingTests
{
    [Fact]
    public void ClientAuthenticationMethodsKeepTheirSpelling()
        => AssertSpelling(typeof(ClientAuthenticationMethods), new Dictionary<string, string>
        {
            [nameof(ClientAuthenticationMethods.ClientSecretBasic)] = "client_secret_basic",
            [nameof(ClientAuthenticationMethods.ClientSecretPost)] = "client_secret_post",
            [nameof(ClientAuthenticationMethods.ClientSecretJwt)] = "client_secret_jwt",
            [nameof(ClientAuthenticationMethods.PrivateKeyJwt)] = "private_key_jwt",
            [nameof(ClientAuthenticationMethods.None)] = "none",
            [nameof(ClientAuthenticationMethods.TlsClientAuth)] = "tls_client_auth",
            [nameof(ClientAuthenticationMethods.SelfSignedTlsClientAuth)] = "self_signed_tls_client_auth",
        });

    [Fact]
    public void CodeChallengeMethodsKeepTheirSpelling()
        => AssertSpelling(typeof(CodeChallengeMethods), new Dictionary<string, string>
        {
            [nameof(CodeChallengeMethods.Plain)] = "plain",
            [nameof(CodeChallengeMethods.S256)] = "S256",
            [nameof(CodeChallengeMethods.S512)] = "S512",
        });

    [Fact]
    public void DisplayModesKeepTheirSpelling()
        => AssertSpelling(typeof(DisplayModes), new Dictionary<string, string>
        {
            [nameof(DisplayModes.Page)] = "page",
            [nameof(DisplayModes.Popup)] = "popup",
            [nameof(DisplayModes.Touch)] = "touch",
            [nameof(DisplayModes.Wap)] = "wap",
        });

    [Fact]
    public void ErrorCodesKeepTheirSpelling()
        => AssertSpelling(typeof(ErrorCodes), new Dictionary<string, string>
        {
            [nameof(ErrorCodes.ConfirmationRequired)] = "confirmation_required",
            [nameof(ErrorCodes.InvalidTarget)] = "invalid_target",
            [nameof(ErrorCodes.AuthorizationPending)] = "authorization_pending",
            [nameof(ErrorCodes.SlowDown)] = "slow_down",
            [nameof(ErrorCodes.ExpiredToken)] = "expired_token",
            [nameof(ErrorCodes.ExpiredLoginHintToken)] = "expired_login_hint_token",
            [nameof(ErrorCodes.UnknownUserId)] = "unknown_user_id",
            [nameof(ErrorCodes.MissingUserCode)] = "missing_user_code",
            [nameof(ErrorCodes.InvalidUserCode)] = "invalid_user_code",
            [nameof(ErrorCodes.InvalidBindingMessage)] = "invalid_binding_message",
            [nameof(ErrorCodes.InvalidToken)] = "invalid_token",
            [nameof(ErrorCodes.InvalidDPoPProof)] = "invalid_dpop_proof",
            [nameof(ErrorCodes.UseDPoPNonce)] = "use_dpop_nonce",
            [nameof(ErrorCodes.InsufficientScope)] = "insufficient_scope",
            [nameof(ErrorCodes.InvalidAuthorizationDetails)] = "invalid_authorization_details",
            [nameof(ErrorCodes.InvalidRequest)] = "invalid_request",
            [nameof(ErrorCodes.InvalidClient)] = "invalid_client",
            [nameof(ErrorCodes.InvalidGrant)] = "invalid_grant",
            [nameof(ErrorCodes.UnauthorizedClient)] = "unauthorized_client",
            [nameof(ErrorCodes.UnsupportedGrantType)] = "unsupported_grant_type",
            [nameof(ErrorCodes.InvalidScope)] = "invalid_scope",
            [nameof(ErrorCodes.AccessDenied)] = "access_denied",
            [nameof(ErrorCodes.TransactionFailed)] = "transaction_failed",
            [nameof(ErrorCodes.UnsupportedResponseType)] = "unsupported_response_type",
            [nameof(ErrorCodes.ServerError)] = "server_error",
            [nameof(ErrorCodes.TemporarilyUnavailable)] = "temporarily_unavailable",
            [nameof(ErrorCodes.InteractionRequired)] = "interaction_required",
            [nameof(ErrorCodes.LoginRequired)] = "login_required",
            [nameof(ErrorCodes.AccountSelectionRequired)] = "account_selection_required",
            [nameof(ErrorCodes.UnmetAuthenticationRequirements)] = "unmet_authentication_requirements",
            [nameof(ErrorCodes.ConsentRequired)] = "consent_required",
            [nameof(ErrorCodes.InvalidRequestUri)] = "invalid_request_uri",
            [nameof(ErrorCodes.InvalidRequestObject)] = "invalid_request_object",
            [nameof(ErrorCodes.RequestNotSupported)] = "request_not_supported",
            [nameof(ErrorCodes.RequestUriNotSupported)] = "request_uri_not_supported",
            [nameof(ErrorCodes.RegistrationNotSupported)] = "registration_not_supported",
            [nameof(ErrorCodes.UnsupportedTokenType)] = "unsupported_token_type",
            [nameof(ErrorCodes.InvalidRedirectUri)] = "invalid_redirect_uri",
            [nameof(ErrorCodes.InvalidClientMetadata)] = "invalid_client_metadata",
            [nameof(ErrorCodes.InvalidSoftwareStatement)] = "invalid_software_statement",
            [nameof(ErrorCodes.UnapprovedSoftwareStatement)] = "unapproved_software_statement",
        });

    [Fact]
    public void GrantTypesKeepTheirSpelling()
        => AssertSpelling(typeof(GrantTypes), new Dictionary<string, string>
        {
            [nameof(GrantTypes.AuthorizationCode)] = "authorization_code",
            [nameof(GrantTypes.ClientCredentials)] = "client_credentials",
            [nameof(GrantTypes.RefreshToken)] = "refresh_token",
            [nameof(GrantTypes.Implicit)] = "implicit",
            [nameof(GrantTypes.Password)] = "password",
            [nameof(GrantTypes.Ciba)] = "urn:openid:params:grant-type:ciba",
            [nameof(GrantTypes.JwtBearer)] = "urn:ietf:params:oauth:grant-type:jwt-bearer",
            [nameof(GrantTypes.DeviceAuthorization)] = "urn:ietf:params:oauth:grant-type:device_code",
            [nameof(GrantTypes.TokenExchange)] = "urn:ietf:params:oauth:grant-type:token-exchange",
        });

    [Fact]
    public void PromptsKeepTheirSpelling()
        => AssertSpelling(typeof(Prompts), new Dictionary<string, string>
        {
            [nameof(Prompts.None)] = "none",
            [nameof(Prompts.Login)] = "login",
            [nameof(Prompts.Consent)] = "consent",
            [nameof(Prompts.SelectAccount)] = "select_account",
            [nameof(Prompts.Create)] = "create",
        });

    [Fact]
    public void ResponseModesKeepTheirSpelling()
        => AssertSpelling(typeof(ResponseModes), new Dictionary<string, string>
        {
            [nameof(ResponseModes.FormPost)] = "form_post",
            [nameof(ResponseModes.Query)] = "query",
            [nameof(ResponseModes.Fragment)] = "fragment",
            [nameof(ResponseModes.QueryJwt)] = "query.jwt",
            [nameof(ResponseModes.FragmentJwt)] = "fragment.jwt",
            [nameof(ResponseModes.FormPostJwt)] = "form_post.jwt",
            [nameof(ResponseModes.Jwt)] = "jwt",
        });

    [Fact]
    public void ResponseTypesKeepTheirSpelling()
        => AssertSpelling(typeof(ResponseTypes), new Dictionary<string, string>
        {
            [nameof(ResponseTypes.Code)] = "code",
            [nameof(ResponseTypes.Token)] = "token",
            [nameof(ResponseTypes.IdToken)] = "id_token",
            [nameof(ResponseTypes.None)] = "none",
        });

    [Fact]
    public void ScopesKeepTheirSpelling()
        => AssertSpelling(typeof(Scopes), new Dictionary<string, string>
        {
            [nameof(Scopes.OpenId)] = "openid",
            [nameof(Scopes.Profile)] = "profile",
            [nameof(Scopes.Email)] = "email",
            [nameof(Scopes.Phone)] = "phone",
            [nameof(Scopes.OfflineAccess)] = "offline_access",
            [nameof(Scopes.Address)] = "address",
        });

    [Fact]
    public void TokenExchangeTokenTypesKeepTheirSpelling()
        => AssertSpelling(typeof(TokenExchangeTokenTypes), new Dictionary<string, string>
        {
            [nameof(TokenExchangeTokenTypes.AccessToken)] = "urn:ietf:params:oauth:token-type:access_token",
            [nameof(TokenExchangeTokenTypes.RefreshToken)] = "urn:ietf:params:oauth:token-type:refresh_token",
            [nameof(TokenExchangeTokenTypes.IdToken)] = "urn:ietf:params:oauth:token-type:id_token",
            [nameof(TokenExchangeTokenTypes.Jwt)] = "urn:ietf:params:oauth:token-type:jwt",
            [nameof(TokenExchangeTokenTypes.Saml1)] = "urn:ietf:params:oauth:token-type:saml1",
            [nameof(TokenExchangeTokenTypes.Saml2)] = "urn:ietf:params:oauth:token-type:saml2",
        });

    [Fact]
    public void TokenTypeHintsKeepTheirSpelling()
        => AssertSpelling(typeof(TokenTypeHints), new Dictionary<string, string>
        {
            [nameof(TokenTypeHints.AccessToken)] = "access_token",
            [nameof(TokenTypeHints.RefreshToken)] = "refresh_token",
        });

    [Fact]
    public void TokenTypesKeepTheirSpelling()
        => AssertSpelling(typeof(TokenTypes), new Dictionary<string, string>
        {
            [nameof(TokenTypes.Basic)] = "Basic",
            [nameof(TokenTypes.Bearer)] = "Bearer",
            [nameof(TokenTypes.DPoP)] = "DPoP",
        });

    private static void AssertSpelling(Type vocabulary, Dictionary<string, string> expected)
    {
        var actual = vocabulary
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.IsLiteral)
            .ToDictionary(field => field.Name, field => (string)field.GetRawConstantValue()!);

        Assert.Equal(
            expected.OrderBy(pair => pair.Key, StringComparer.Ordinal),
            actual.OrderBy(pair => pair.Key, StringComparer.Ordinal));
    }
}
