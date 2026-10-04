// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Model;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A token one tenant issued is honoured by no other: the other tenant neither reports it active, nor revokes it, nor
/// refreshes it, though the same client id and secret authenticate at both.
/// </summary>
public sealed partial class TenantIsolationTests
{
    private const string IntrospectionPath = "/connect/introspect";
    private const string RevocationPath = "/connect/revoke";

    private async Task<bool> ActiveAtAsync(string tenant, string token)
    {
        var response = await PostAsync(tenant, IntrospectionPath, PairwiseClientId,
            new Dictionary<string, string> { [IntrospectionRequest.Parameters.Token] = token });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await ReadJsonAsync(response))[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>();
    }

    /// <summary>
    /// An access token of one tenant is active there and inactive at the other.
    /// </summary>
    [Fact]
    public async Task AnAccessTokenOfOneTenant_IsInactiveAtTheOther()
    {
        var accessToken = await AccessTokenOfADeviceFlowAsync(Acme);

        Assert.True(await ActiveAtAsync(Acme, accessToken));
        Assert.False(await ActiveAtAsync(Globex, accessToken));
    }

    /// <summary>
    /// Revoking a token of one tenant at the other leaves it active where it was issued, and revoking it there ends it.
    /// </summary>
    [Fact]
    public async Task ARevocationAtTheOtherTenant_LeavesTheTokenActive()
    {
        var accessToken = await AccessTokenOfADeviceFlowAsync(Acme);

        Task<HttpResponseMessage> RevokeAtAsync(string tenant) => PostAsync(tenant, RevocationPath, PairwiseClientId,
            new Dictionary<string, string> { [RevocationRequest.Parameters.Token] = accessToken });

        Assert.Equal(HttpStatusCode.OK, (await RevokeAtAsync(Globex)).StatusCode);
        Assert.True(await ActiveAtAsync(Acme, accessToken));

        Assert.Equal(HttpStatusCode.OK, (await RevokeAtAsync(Acme)).StatusCode);
        Assert.False(await ActiveAtAsync(Acme, accessToken));
    }

    /// <summary>
    /// A refresh token of one tenant is refused at the other and still refreshes where it was issued.
    /// </summary>
    [Fact]
    public async Task ARefreshTokenOfOneTenant_IsRefusedAtTheOther()
    {
        var tokens = await TokensOfADeviceFlowAsync(Acme, $"{Scopes.OpenId} {Scopes.OfflineAccess}");
        var refreshToken = tokens[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

        Dictionary<string, string> Refresh() => new()
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.RefreshToken,
            [TokenRequest.Parameters.RefreshToken] = refreshToken,
        };

        var atGlobex = await PostAsync(Globex, TokenPath, PairwiseClientId, Refresh());
        Assert.Equal(HttpStatusCode.BadRequest, atGlobex.StatusCode);
        Assert.Equal(
            ErrorCodes.InvalidGrant,
            (await ReadJsonAsync(atGlobex))[ResponseParameters.Error]?.GetValue<string>());

        var atAcme = await PostAsync(Acme, TokenPath, PairwiseClientId, Refresh());
        Assert.Equal(HttpStatusCode.OK, atAcme.StatusCode);
        Assert.NotNull((await ReadJsonAsync(atAcme))[ResponseParameters.AccessToken]);
    }
}
