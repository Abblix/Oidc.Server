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

using System.Collections.Generic;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common;

public class AuthorizationContextExtensionsTests
{
    [Fact]
    public void SerializeDeserializeTest()
    {
        var ac = new AuthorizationContext(
            "clientId",
            ["scope1", "scope2"],
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
