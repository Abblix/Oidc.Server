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

using System.Net.Mime;
using System.Xml;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Server.Mvc.ActionResults;

/// <summary>
/// Provides a base class for action results that generate HTML content.
/// </summary>
/// <remarks>
/// This abstract class is designed to be inherited by classes that need to dynamically generate HTML content as an action result.
/// It sets various HTTP headers to ensure that the generated content is not cached and is served as HTML.
/// </remarks>
public abstract class GeneratedHtmlResult : ActionResult, IStatusCodeActionResult
{
	/// <summary>
	/// Gets the HTTP status code to be set in the response.
	/// Defaults to 200 (OK) if not set.
	/// </summary>
	public int? StatusCode { init; get; } = StatusCodes.Status200OK;

	/// <summary>
	/// Asynchronously executes the result operation of the action method, setting HTTP headers and writing the HTML content to the response.
	/// </summary>
	/// <param name="context">The action context for the current request.</param>
	public override async Task ExecuteResultAsync(ActionContext context)
	{
		var response = context.HttpContext.Response;

		if (StatusCode != null)
			response.StatusCode = StatusCode.Value;

		var headers = response.GetTypedHeaders();
		headers.Expires = DateTimeOffset.UnixEpoch;
		headers.CacheControl = new CacheControlHeaderValue
		{
			MaxAge = TimeSpan.Zero,
			SharedMaxAge = TimeSpan.Zero,
			NoStore = true,
			NoCache = true,
		};
		response.Headers.Pragma = "no-cache";
		response.ContentType = MediaTypeNames.Text.Html;

		await using var streamWriter = new StreamWriter(
			response.Body,
			leaveOpen: true);

		await using var xmlWriter = XmlWriter.Create(
			streamWriter,
			new XmlWriterSettings
			{
				OmitXmlDeclaration = true,
				Indent = false,
				CloseOutput = false,
				Async = true,
			});

		await WriteHtmlAsync(xmlWriter);
	}

	/// <summary>
	/// When overridden in a derived class, writes the HTML content to be rendered to the specified XML writer.
	/// </summary>
	/// <param name="writer">The XML writer used to write the HTML content.</param>
	protected abstract Task WriteHtmlAsync(XmlWriter writer);
}
