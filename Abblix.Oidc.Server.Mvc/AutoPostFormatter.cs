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
