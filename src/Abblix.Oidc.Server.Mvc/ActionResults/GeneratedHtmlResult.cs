// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using System.Diagnostics.CodeAnalysis;
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
[Obsolete("Nothing derives from this type. The form_post response it was written for is produced by " +
          "AuthorizationResponseFormatter instead, and no derived class exists in this library or its tests. " +
          "It will be removed in the next major version; if you derive from it, say so on issue #303.")]
[SuppressMessage("Major Code Smell", "S1133:Deprecated code should be removed",
    Justification = "Removal is scheduled and tracked: the type is public and abstract, so a consumer outside " +
                    "this repository could derive from it, which makes deletion a break rather than a cleanup " +
                    "and puts it on the next major version (#303).")]
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
