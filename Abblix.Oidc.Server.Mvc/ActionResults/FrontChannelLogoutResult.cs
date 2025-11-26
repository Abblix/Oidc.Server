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

using System.Web;
using System.Xml;

namespace Abblix.Oidc.Server.Mvc.ActionResults;

/// <summary>
/// Generates an HTML response that handles front-channel logout by embedding iframes for each logout URI.
/// </summary>
/// <remarks>
/// This class is responsible for creating an HTML page containing iframes for each URI in the front-channel logout process.
/// The iframes are used to send logout requests to all clients participating in the user's session.
/// The 'barrierSync' function ensures that the user is redirected to the post-logout URI only after all iframes have loaded,
/// indicating that logout requests have been sent to all clients.
/// </remarks>
/// <param name="postLogOutUri">The URI to redirect to after the front-channel logout process is complete.</param>
/// <param name="frontChannelLogoutUris">A list of URIs for the iframes to be used in the front-channel logout process.</param>
public class FrontChannelLogoutResult(
    Uri? postLogOutUri,
    IList<Uri> frontChannelLogoutUris) : GeneratedHtmlResult
{
    /// <summary>
    /// Asynchronously writes the HTML content that includes iframes for each front-channel logout URI and
    /// a script to redirect to the post-logout URI.
    /// </summary>
    /// <param name="writer">The XML writer used to write the HTML content.</param>
    protected override async Task WriteHtmlAsync(XmlWriter writer)
    {
        await writer.WriteDocTypeAsync("html", null, null, null);

        writer.WriteStartElement("html");
        writer.WriteStartElement("head");

        writer.WriteElementString("style", "iframe { display: none; width: 0; height: 0; }");
        writer.WriteStartElement("script");
        await writer.WriteStringAsync($"var count = {frontChannelLogoutUris.Count}; ");

        if (postLogOutUri != null)
        {
            var postLogOutUriEncoded = HttpUtility.JavaScriptStringEncode(postLogOutUri.OriginalString, true);

            await writer.WriteStringAsync("function barrierSync() { ");
            await writer.WriteStringAsync("if (--count === 0) ");
            await writer.WriteStringAsync($"window.location.replace({postLogOutUriEncoded}); ");
            await writer.WriteStringAsync("}");
        }

        await writer.WriteEndElementAsync(); // </script>
        await writer.WriteEndElementAsync(); // </head>

        writer.WriteStartElement("body");
        foreach (var uri in frontChannelLogoutUris)
        {
            writer.WriteStartElement("iframe");
            writer.WriteAttributeString("onload", "barrierSync()");
            writer.WriteAttributeString("src", uri.OriginalString);
            await writer.WriteEndElementAsync(); // </iframe>
        }

        await writer.WriteEndElementAsync(); // </body>
        await writer.WriteEndElementAsync(); // </html>
    }
}
