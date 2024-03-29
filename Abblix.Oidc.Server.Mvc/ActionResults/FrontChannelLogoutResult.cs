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
public class FrontChannelLogoutResult : GeneratedHtmlResult
{
    /// <summary>
    /// Initializes a new instance of the <see cref="FrontChannelLogoutResult"/> class.
    /// </summary>
    /// <param name="postLogOutUri">The URI to redirect to after the front-channel logout process is complete.</param>
    /// <param name="frontChannelLogoutUris">A list of URIs for the iframes to be used in the front-channel logout process.</param>
    public FrontChannelLogoutResult(
        Uri? postLogOutUri,
        IList<Uri> frontChannelLogoutUris)
    {
        _postLogOutUri = postLogOutUri;
        _frontChannelLogoutUris = frontChannelLogoutUris;
    }

    private readonly IList<Uri> _frontChannelLogoutUris;
    private readonly Uri? _postLogOutUri;

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
        await writer.WriteStringAsync($"var count = {_frontChannelLogoutUris.Count}; ");

        if (_postLogOutUri != null)
        {
            var postLogOutUri = HttpUtility.JavaScriptStringEncode(_postLogOutUri.OriginalString, true);

            await writer.WriteStringAsync("function barrierSync() { ");
            await writer.WriteStringAsync("if (--count === 0) ");
            await writer.WriteStringAsync($"window.location.replace({postLogOutUri}); ");
            await writer.WriteStringAsync("}");
        }

        await writer.WriteEndElementAsync(); // </script>
        await writer.WriteEndElementAsync(); // </head>

        writer.WriteStartElement("body");
        foreach (var uri in _frontChannelLogoutUris)
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
