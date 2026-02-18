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

using System.Net.Mime;
using System.Xml;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;

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
	/// <inheritdoc />
	public int? StatusCode { init; get; } = StatusCodes.Status200OK;

	/// <summary>
	/// Asynchronously executes the result operation of the action method, setting HTTP headers and writing the HTML content to the response.
	/// </summary>
	/// <param name="context">The action context for the current request.</param>
	public override async Task ExecuteResultAsync(ActionContext context)
	{
		var response = context.HttpContext.Response;

		if (StatusCode.HasValue)
			response.StatusCode = StatusCode.Value;

		response.SetNoCacheHeaders();
		response.ContentType = MediaTypeNames.Text.Html;

		await using var streamWriter = new StreamWriter(response.Body, leaveOpen: true);

		await using var xmlWriter = XmlWriter.Create(
			streamWriter,
			new()
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
