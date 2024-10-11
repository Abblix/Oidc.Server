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
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Model;

public class ClientRegistrationRequestTest
{
    [Theory]
    [InlineData(
        "{\"client_name\":\"dynamic_client_1 RqxLk9BdhK8qC3z\",\"grant_types\":[\"implicit\"],\"jwks\":{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"gUOdYo2PpUUnZzozIPJ-7mK2Z5jYBxjj_5iB2TDnElt8yUc-mcCeOQrsaswPgKx2KMSJ50kwrFHHEuNyiDhgNMgtmJ98RuhggXaPF1fmmHss_Wc1OSqyGYLWbEzYGsRck5yTVP4xsPYAeP5xkkLze_FXJvwITNu2aGxXEYwokkrcWgL3AsXtYKClIwmacHhVNEMn-ALe3sMTifx4F8TqmNAlD4FPga094txHJNo2Ho6z4kn5L4uq_WXklDjaIDOqQZtdn0emXig3RHQcOtepFcXt7pcK9E2M3kxKFOMPpY8c4kaDfQ41jv23vbm9oDTh5s3TB0ZwcKJXj4-06gwTWw\"}]},\"token_endpoint_auth_method\":\"client_secret_basic\",\"response_types\":[\"id_token token\"],\"redirect_uris\":[\"https://www.certification.openid.net/test/a/Abblix/callback\"],\"contacts\":[\"certification@oidf.org\"]}")]
    public void DeserializeClientRegistrationRequestTest(string json)
    {
        JsonSerializer.Deserialize<ClientRegistrationRequest>(json);
    }
}
