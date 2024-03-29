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
using System.Text;
using System.Xml;
using Abblix.Oidc.Server.Mvc.Binders;
using Microsoft.AspNetCore.Mvc.Formatters;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// A custom text output formatter that generates an HTML form with auto-submit functionality.
/// This formatter is designed to output HTML content that automatically submits a POST request to a specified URI
/// with given parameters when loaded in a browser.
/// </summary>
public class AutoPostFormatter : TextOutputFormatter
{
	/// <summary>
	/// Initializes a new instance of the <see cref="AutoPostFormatter"/> class.
	/// </summary>
	/// <param name="parametersProvider">Provider to retrieve the parameters for the form.</param>
	/// <param name="action">The URI where the form will be submitted.</param>
	public AutoPostFormatter(IParametersProvider parametersProvider, Uri action)
	{
		_parametersProvider = parametersProvider;
		_action = action;

		SupportedMediaTypes.Add(MediaTypeNames.Text.Html);
		SupportedEncodings.Add(Encoding.UTF8);
	}

	private readonly IParametersProvider _parametersProvider;
	private readonly Uri _action;

	/// <summary>
	/// Writes the HTML content to the response body asynchronously.
	/// This method overrides the base class implementation to write an HTML form with the specified parameters.
	/// </summary>
	/// <param name="context">The context for the output formatter.</param>
	/// <param name="encoding">The encoding to use for the response.</param>
	/// <returns>A task that represents the asynchronous write operation.</returns>
	public override async Task WriteResponseBodyAsync(OutputFormatterWriteContext context, Encoding encoding)
	{
		if (context.Object == null)
			return;

		var settings = new XmlWriterSettings { Async = true, Encoding = encoding };
		await using var writer = XmlWriter.Create(context.HttpContext.Response.Body, settings);

		var parameters = _parametersProvider.GetParameters(context.Object);
		
		await WriteHtmlAsync(writer, parameters);
	}

	/// <summary>
	/// Asynchronously writes the HTML form elements using the provided <see cref="XmlWriter"/>.
	/// The form is auto-submitted using JavaScript when loaded in the browser.
	/// </summary>
	/// <param name="writer">The XML writer to write the HTML content.</param>
	/// <param name="parameters">The collection of parameters to include in the form.</param>
	/// <returns>A task that represents the asynchronous write operation.</returns>
	private async Task WriteHtmlAsync(
		XmlWriter writer,
		IEnumerable<(string name, string? value)> parameters)
	{
		await writer.WriteDocTypeAsync("html", null, null, null);
		writer.WriteStartElement("html");
		{
			writer.WriteStartElement("head");
			{
				writer.WriteElementString("title", "Working...");
			}
			await writer.WriteEndElementAsync();

			writer.WriteStartElement("body");
			writer.WriteAttributeString("onload", "javascript:document.forms[0].submit()");
			{
				writer.WriteStartElement("form");
				writer.WriteAttributeString("method", "POST");
				writer.WriteAttributeString("action", _action.OriginalString);
				{
					foreach (var (name, value) in parameters)
					{
						if (string.IsNullOrEmpty(value))
							continue;

						writer.WriteStartElement("input");
						writer.WriteAttributeString("type", "hidden");
						writer.WriteAttributeString("name", name);
						writer.WriteAttributeString("value", value);
						await writer.WriteEndElementAsync();
					}

					writer.WriteStartElement("noscript");
					{
						writer.WriteElementString("p", "JavaScript is disabled. Click Submit to continue.");
						writer.WriteStartElement("input");
						writer.WriteAttributeString("type", "submit");
						writer.WriteAttributeString("value", "Submit");
						await writer.WriteEndElementAsync(); //input
					}
					await writer.WriteEndElementAsync(); //noscript
				}
				await writer.WriteEndElementAsync(); //form
			}
			await writer.WriteEndElementAsync(); //body
		}
		await writer.WriteEndElementAsync(); //html
	}
}
