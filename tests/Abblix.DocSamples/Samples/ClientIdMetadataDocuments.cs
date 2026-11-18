// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server


// <ambient>
using Microsoft.AspNetCore.Builder;
// </ambient>
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.MinimalApi;

namespace Abblix.DocSamples.Samples;

/// <summary>
/// The compiled copy of the Client ID Metadata Documents sample in the README of Abblix.Oidc.Server.
/// </summary>
internal static class ClientIdMetadataDocumentsSample
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S1075",
        Justification = "The README shows the addresses a reader replaces with their own.")]
    internal static void Configure(string[] args)
    {
        // <sample>
        // Client ID Metadata Documents are experimental until the draft becomes an RFC
#pragma warning disable ABX9001

        var builder = WebApplication.CreateBuilder(args);

        builder.Services
            .AddOidcServices(options =>
            {
                // Optional: fetch documents only from URLs starting with these prefixes
                options.ClientIdMetadataDocuments.AllowedClientIdPrefixes = ["https://apps.example.com/"];
            })
            .AddClientIdMetadataDocuments();
        // </sample>
    }
}
