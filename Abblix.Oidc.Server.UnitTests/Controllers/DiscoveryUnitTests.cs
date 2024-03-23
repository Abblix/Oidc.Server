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

namespace Abblix.Oidc.Server.UnitTests.Controllers;

public class DiscoveryUnitTests
{
	//[DataTestMethod]
	//[TestCase(ResponseTypes.None, "\"none\"")]
	//[TestCase(ResponseTypes.IdToken, "\"id_token\"")]
	//[TestCase(ResponseTypes.IdToken | ResponseTypes.Token, "\"token id_token\"")]
	//public void FlagsEnumStringConverterTest(string[] source, string expected)
	//{
	//	var options = new JsonSerializerOptions { Converters = { new EnumStringConverter() } };
	//	var json = JsonSerializer.Serialize(source, options);
	//	Assert.AreEqual(expected, json);

	//	var deserialized = JsonSerializer.Deserialize<ResponseTypes>(json, options);
	//	Assert.AreEqual(source, deserialized);
	//}

	//[DataTestMethod]
	//[TestCase(GrantType.AuthorizationCode, "\"authorization_code\"")]
	//[TestCase(GrantType.ClientCredentials, "\"client_credentials\"")]
	//[TestCase(GrantType.RefreshToken, "\"refresh_token\"")]
	//[TestCase(GrantType.Implicit, "\"implicit\"")]
	//[TestCase(GrantType.Password, "\"password\"")]
	//public void EnumStringConverterTest(GrantType source, string expected)
	//{
	//	var options = new JsonSerializerOptions { Converters = { new EnumStringConverter() } };
	//	var json = JsonSerializer.Serialize(source, options);
	//	Assert.AreEqual(expected, json);

	//	var deserialized = JsonSerializer.Deserialize<GrantType>(json, options);
	//	Assert.AreEqual(source, deserialized);
	//}
}
