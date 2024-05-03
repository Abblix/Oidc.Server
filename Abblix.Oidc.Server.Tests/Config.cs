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

	public ClientSettings AccountManagementApp { get; set; }
	public ClientSettings ApClientSampleCode { get; set; }
	public Uri BaseUrl { get; set; }
	public string Login { get; set; }
	public string Password { get; set; }

	public class ClientSettings
	{
		public string ClientId { get; set; }
		public string ClientSecret { get; set; }
		public Uri RedirectUri { get; set; }
	}
}
