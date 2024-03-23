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

using System;
using System.IO;

using Microsoft.Extensions.Configuration;



namespace Abblix.Oidc.Server.Tests;

public sealed class Config
{
	private static IConfiguration GetTestConfiguration(string fileName = "appSettings.json")
	{
		var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");

		var fileNameWithoutExtension = Path.GetFileNameWithoutExtension(fileName);
		var extension = Path.GetExtension(fileName);

		return new ConfigurationBuilder()
			.AddJsonFile(fileName, optional: false, reloadOnChange: false)
			.AddJsonFile($"{fileNameWithoutExtension}.{environment}{extension}", optional: true, reloadOnChange: false)
			.Build();
	}

	private static readonly IConfiguration AppSettings = GetTestConfiguration();

	public Config() => AppSettings.Bind(this);

	public string KasperskyIdDatabase { get; set; }
	public Uri UisBaseUrl { get; set; }

	public ClientSettings AccountManagementApp { get; set; }
	public ClientSettings ApClientSampleCode { get; set; }

	public Uri BaseUrl { get; set; }

	public string Realm { get; set; }
	public string Login { get; set; }
	public string Password { get; set; }

	public class ClientSettings
	{
		public string ClientId { get; set; }
		public string ClientSecret { get; set; }
		public Uri RedirectUri { get; set; }
	}
}
