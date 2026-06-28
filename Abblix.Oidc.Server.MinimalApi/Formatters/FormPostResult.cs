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

using System.Text;
using System.Xml;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Delivers authorization-response parameters via the OAuth 2.0 Form Post Response Mode: a self-submitting HTML form
/// whose hidden inputs carry the parameters, auto-submitted to the client's redirect URI on load, with a manual
/// submit fallback when scripting is disabled.
/// </summary>
internal sealed class FormPostResult(IParametersProvider parametersProvider, object payload, Uri action) : IResult
{
    public async Task ExecuteAsync(HttpContext httpContext)
    {
        var response = httpContext.Response;
        response.ContentType = "text/html; charset=utf-8";

        var settings = new XmlWriterSettings { Async = true, Encoding = Encoding.UTF8 };
        await using var writer = XmlWriter.Create(response.Body, settings);

        var parameters = parametersProvider.GetParameters(payload);
        await WriteHtmlAsync(writer, parameters);
    }

    private async Task WriteHtmlAsync(XmlWriter writer, IEnumerable<(string name, string? value)> parameters)
    {
        await writer.WriteDocTypeAsync("html", null, null, null);
        writer.WriteStartElement("html");
        await WriteHeadAsync(writer);
        await WriteBodyAsync(writer, parameters);
        await writer.WriteEndElementAsync();
    }

    private static async Task WriteHeadAsync(XmlWriter writer)
    {
        writer.WriteStartElement("head");
        writer.WriteElementString("title", "Working...");
        await writer.WriteEndElementAsync();
    }

    private async Task WriteBodyAsync(XmlWriter writer, IEnumerable<(string name, string? value)> parameters)
    {
        writer.WriteStartElement("body");
        writer.WriteAttributeString("onload", "javascript:document.forms[0].submit()");
        await WriteFormAsync(writer, parameters);
        await writer.WriteEndElementAsync();
    }

    private async Task WriteFormAsync(XmlWriter writer, IEnumerable<(string name, string? value)> parameters)
    {
        writer.WriteStartElement("form");
        writer.WriteAttributeString("method", "POST");
        writer.WriteAttributeString("action", action.OriginalString);
        await WriteHiddenInputsAsync(writer, parameters);
        await WriteNoScriptAsync(writer);
        await writer.WriteEndElementAsync();
    }

    private static async Task WriteHiddenInputsAsync(XmlWriter writer, IEnumerable<(string name, string? value)> parameters)
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
    }

    private static async Task WriteNoScriptAsync(XmlWriter writer)
    {
        writer.WriteStartElement("noscript");
        writer.WriteElementString("p", "JavaScript is disabled. Click Submit to continue.");
        writer.WriteStartElement("input");
        writer.WriteAttributeString("type", "submit");
        writer.WriteAttributeString("value", "Submit");
        await writer.WriteEndElementAsync();
        await writer.WriteEndElementAsync();
    }
}
