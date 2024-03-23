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
        var request = JsonSerializer.Deserialize<ClientRegistrationRequest>(json);
    }
}
