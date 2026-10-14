// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Mvc.Binders;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Describes the fields of the library's request models as a client sends them.
/// </summary>
internal sealed class WireFieldDescriber(IModelMetadataProvider metadataProvider)
{
    /// <summary>
    /// Describes each field the library reads once, under its protocol name, as the type the request carries.
    /// </summary>
    /// <remarks>
    /// A field read the way the platform reads a value keeps the platform's description: <c>resource</c> stays an
    /// array a client may repeat, <c>redirect_uri</c> an address. A field read through a binder of the library's own is
    /// described by what that binder reads, since its CLR type is not what travels: <c>claims</c> is one field holding
    /// JSON, not the members of its type; <c>max_age</c> is a number of seconds, not a time span; <c>scope</c> is one
    /// space-separated string, not an array. The client's certificate comes from the connection, not from the request,
    /// so it is not a parameter at all. Each field is described once, which a document generator keying a form's fields
    /// by name requires: the pushed authorization request reads <c>client_id</c> from both models it binds.
    /// </remarks>
    public void Describe(ApiDescription description)
    {
        var bound = description.ActionDescriptor.Parameters
            .Where(parameter => parameter.BindingInfo?.BindingSource is { IsFromRequest: true })
            .SelectMany(parameter => metadataProvider.GetMetadataForType(parameter.ParameterType).Properties)
            .Where(property => property.BinderType != null);

        foreach (var property in bound)
            DescribeOnce(description, property);
    }

    /// <summary>
    /// Replaces what the platform described for the field with one description of it, or with none for a value that
    /// does not come from the request.
    /// </summary>
    private void DescribeOnce(ApiDescription description, ModelMetadata property)
    {
        var name = property.BinderModelName ?? property.Name!;
        var described = description.ParameterDescriptions
            .Where(parameter => parameter.Name == name || parameter.Name.StartsWith(name + ".", StringComparison.Ordinal))
            .ToList();
        if (described.Count == 0)
            return;

        var position = description.ParameterDescriptions.IndexOf(described[0]);
        foreach (var parameter in described)
            description.ParameterDescriptions.Remove(parameter);

        if (described[0].Source == BindingSource.Custom)
            return;

        var wireType = WireTypeOf(property.BinderType!);
        var platforms = described.FirstOrDefault(parameter => parameter.Name == name);
        if (wireType == null && platforms != null)
        {
            description.ParameterDescriptions.Insert(position, platforms);
            return;
        }

        // A field of its own, typed both ways a generator reads a type: from the description and from the
        // metadata. It stands apart from the model it was bound into, as the generators treat a top-level field.
        var type = wireType ?? typeof(string);
        description.ParameterDescriptions.Insert(position, new ApiParameterDescription
        {
            Name = name,
            Source = described[0].Source,
            Type = type,
            ModelMetadata = metadataProvider.GetMetadataForType(type),
            IsRequired = property.IsBindingRequired,
            ParameterDescriptor = new ParameterDescriptor
            {
                Name = name,
                ParameterType = type,
                BindingInfo = described[0].ParameterDescriptor?.BindingInfo,
            },
        });
    }

    /// <summary>
    /// The type a field read by the binder travels as, or null where the platform's own reading describes it.
    /// </summary>
    private static Type? WireTypeOf(Type binderType) => binderType switch
    {
        _ when binderType == typeof(RequestParameterBinder) => null,

        _ when binderType == typeof(CustomParameterBinder<SecondsToTimeSpanModelBinder>) => typeof(int),

        _ when binderType == typeof(CustomParameterBinder<SpaceSeparatedValuesBinder>)
               || binderType == typeof(CustomParameterBinder<JsonSerializerModelBinder>)
               || binderType == typeof(CustomParameterBinder<CultureInfoBinder>)
               || binderType == typeof(AuthenticationHeaderBinder) => typeof(string),

        _ => throw new InvalidOperationException(
            $"No type is known for describing a field read by {binderType}; {nameof(WireTypeOf)} needs one."),
    };
}
