// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using System.Collections.Generic;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.Tests;

public class AuthorizationContextExtensionsTests
{
    [Fact]
    public void SerializeDeserializeTest()
    {
        var ac = new AuthorizationContext(
            "clientId",
            new []{ "scope1", "scope2" },
            new RequestedClaims { UserInfo = new Dictionary<string, RequestedClaimDetails>
            {
                { "abc", new RequestedClaimDetails { Essential = true } },
            }});

        var payload = new JsonWebTokenPayload(new JsonObject());
        ac.ApplyTo(payload);
        Assert.Contains(payload.Json, claim => claim.Key == "requested_claims");

        var ac2 = payload.ToAuthorizationContext();
        Assert.NotNull(ac2.RequestedClaims);
        Assert.NotNull(ac2.RequestedClaims.UserInfo);
        Assert.True(ac2.RequestedClaims.UserInfo["abc"].Essential);
    }
}
