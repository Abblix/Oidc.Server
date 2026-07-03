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
using Abblix.Oidc.Server.Mvc.SourceGeneration;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace Abblix.Oidc.Server.MinimalApi.SourceGeneration;

/// <summary>
/// Generates Minimal API request-binding models from the core request models. A hand-written partial record stub
/// marked with the trigger attribute names its core counterpart; the generator emits the matching partial with the
/// bound properties, a static <c>BindAsync(HttpContext)</c> that reads each property from the form, query, headers or
/// TLS connection per the core wire-format markers, and the implicit operator projecting the bound model onto the
/// core type.
/// </summary>
[Generator]
public class MinimalApiModelGenerator : IIncrementalGenerator
{
    // The generator targets netstandard2.0 and analyses the net8+ Abblix assemblies through compilation symbols only,
    // so it mirrors the marker identities as constants instead of referencing the types.
    private const string GeneratedFromAttributeName = "Abblix.Oidc.Server.MinimalApi.Attributes.GeneratedFromAttribute";
    private const string SupportsGetPropertyName = "SupportsGet";
    private const string DeclarativeValidationNamespace = "Abblix.Oidc.Server.DeclarativeValidation";
    private const string DataAnnotationsNamespace = "System.ComponentModel.DataAnnotations";
    private const string SystemTextJsonNamespace = "System.Text.Json.Serialization";
    private const string JsonIgnoreAttributeName = "JsonIgnoreAttribute";
    private const string JsonPropertyNameAttributeName = "JsonPropertyNameAttribute";

    // Wire-format markers — the value conversion each property's bound string(s) goes through.
    private const string SpaceSeparatedStringMarkerName = "SpaceSeparatedStringAttribute";
    private const string TotalSecondsMarkerName = "TotalSecondsAttribute";
    private const string JsonObjectMarkerName = "JsonObjectAttribute";
    private const string CultureListMarkerName = "CultureListAttribute";

    // Transport-source markers — the property is bound from a header or the TLS connection, not a payload value.
    private const string RequestHeaderMarkerName = "RequestHeaderAttribute";
    private const string AuthorizationHeaderMarkerName = "AuthorizationHeaderAttribute";
    private const string ClientCertificateMarkerName = "ClientCertificateAttribute";

    // Validation markers — translated to the executable Minimal API validation attributes of the same name, so a
    // Validator pass over the bound model enforces the rule the core declared.
    private const string AllowedValuesMarkerName = "AllowedValuesAttribute";
    private const string AbsoluteUriMarkerName = "AbsoluteUriAttribute";
    private const string ElementsRequiredMarkerName = "ElementsRequiredAttribute";
    private const string RequiredMarkerName = "RequiredAttribute";

    // The generator emits references to these helper types. Rather than hardcode their fully-qualified names —
    // which silently rot into broken generated code when a type moves namespace — they are resolved to their live
    // symbols per compilation (see KnownTypes). Our own helpers are found by simple name within the compiled
    // assembly, so a namespace move follows automatically; the executable validation attributes live in a
    // referenced assembly and are each resolved by metadata name, so a rename or move of any one of them fails the
    // generation loud instead of emitting a dangling reference.
    private const string FormValuesTypeName = "FormValues";
    private const string RequestValuesTypeName = "RequestValues";
    private const string ValidatableModelTypeName = "IValidatableModel";
    private const string AllowedValuesAttributeName = "Abblix.Utils.Validation.AllowedValuesAttribute";
    private const string AbsoluteUriAttributeName = "Abblix.Utils.Validation.AbsoluteUriAttribute";
    private const string ElementsRequiredAttributeName = "Abblix.Utils.Validation.ElementsRequiredAttribute";

    private static readonly string CompilerServicesNamespace =
        typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute).Namespace!;

    private static readonly SymbolDisplayFormat FullyQualifiedWithNullability =
        SymbolDisplayFormat.FullyQualifiedFormat.AddMiscellaneousOptions(
            SymbolDisplayMiscellaneousOptions.IncludeNullableReferenceTypeModifier);

    private static readonly DiagnosticDescriptor CoreTypeNotFound = new(
        id: "ABXM001",
        title: "Core model type not found",
        messageFormat: "The core model type '{0}' referenced by the generation stub could not be resolved",
        category: "Abblix.Oidc.Server.MinimalApi.SourceGeneration",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor WireNameMissing = new(
        id: "ABXM002",
        title: "Bound property has no wire name",
        messageFormat: "The core property '{0}.{1}' declares no wire-level parameter name and is not excluded " +
                       "from serialization, so the generator cannot emit a binding for it",
        category: "Abblix.Oidc.Server.MinimalApi.SourceGeneration",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor HelperTypeNotFound = new(
        id: "ABXM003",
        title: "Generator helper type not found",
        messageFormat: "The helper type '{0}' the generator emits references to could not be resolved in the " +
                       "compilation, so it was renamed or removed and the generated binders would not compile",
        category: "Abblix.Oidc.Server.MinimalApi.SourceGeneration",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor HelperTypeAmbiguous = new(
        id: "ABXM004",
        title: "Generator helper type is ambiguous",
        messageFormat: "The helper type name '{0}' resolves to more than one type in the compilation, so the " +
                       "generator cannot pick the one to reference",
        category: "Abblix.Oidc.Server.MinimalApi.SourceGeneration",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    /// <inheritdoc />
    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        var stubs = context.SyntaxProvider.ForAttributeWithMetadataName(
            GeneratedFromAttributeName,
            predicate: static (node, _) => node is RecordDeclarationSyntax,
            transform: static (ctx, _) => ExtractStub(ctx));

        // The helper types the generator emits references to are resolved once per compilation to their live
        // symbols; their fully-qualified names then flow into every model. Resolution failures are reported once
        // here rather than duplicated onto each generated model.
        var knownTypes = context.CompilationProvider.Select(static (compilation, _) => KnownTypesResult.Resolve(compilation));

        context.RegisterSourceOutput(knownTypes, static (productionContext, resolved) =>
        {
            foreach (var diagnostic in resolved.Diagnostics)
                productionContext.ReportDiagnostic(diagnostic.ToDiagnostic());
        });

        var outputs = stubs
            .Combine(knownTypes)
            .Combine(context.CompilationProvider)
            .Select(static (pair, _) => Generate(pair.Left.Left, pair.Left.Right, pair.Right));

        context.RegisterSourceOutput(outputs, static (productionContext, result) =>
        {
            foreach (var diagnostic in result.Diagnostics)
                productionContext.ReportDiagnostic(diagnostic.ToDiagnostic());

            if (result.Source != null)
                productionContext.AddSource(result.HintName, SourceText.From(result.Source, Encoding.UTF8));
        });
    }

    private static StubInfo ExtractStub(GeneratorAttributeSyntaxContext context)
    {
        var stubType = (INamedTypeSymbol)context.TargetSymbol;
        var attribute = context.Attributes[0];

        var coreTypeName = attribute.ConstructorArguments is [{ Value: INamedTypeSymbol coreType } _]
            ? $"{coreType.ContainingNamespace.ToDisplayString()}.{coreType.MetadataName}"
            : string.Empty;

        var supportsGet = attribute.NamedArguments
            .Any(static argument => argument is { Key: SupportsGetPropertyName, Value.Value: true });

        return new StubInfo(
            stubType.ContainingNamespace.ToDisplayString(),
            stubType.Name,
            coreTypeName,
            supportsGet,
            LocationInfo.From(context.TargetNode.GetLocation()));
    }

    private static GenerationResult Generate(StubInfo stub, KnownTypesResult knownTypes, Compilation compilation)
    {
        // A helper the generator relies on could not be resolved; the diagnostic was already reported once against
        // the compilation, so emit no source rather than a model that would not compile.
        if (knownTypes.Types is not { } known)
            return new GenerationResult($"{stub.Namespace}.{stub.Name}.g.cs", null, new EquatableArray<DiagnosticInfo>([]));

        var coreType = compilation.GetTypeByMetadataName(stub.CoreTypeName);
        if (coreType == null)
        {
            return new GenerationResult(
                $"{stub.Namespace}.{stub.Name}.g.cs",
                null,
                new EquatableArray<DiagnosticInfo>([new DiagnosticInfo(CoreTypeNotFound, stub.Location, stub.CoreTypeName)]));
        }

        return new ModelEmitter(stub, coreType, known).Emit();
    }

    /// <summary>The fully-qualified names of the helper types the generator emits references to.</summary>
    private sealed record KnownTypes(
        string FormValues, string RequestValues, string ValidatableModel,
        string AllowedValues, string AbsoluteUri, string ElementsRequired);

    /// <summary>
    /// The resolved <see cref="KnownTypes"/>, or — when a helper type could not be resolved — the diagnostics to
    /// report. Kept as equatable data so the pipeline re-renders models only when the resolved names actually change.
    /// </summary>
    private sealed record KnownTypesResult(KnownTypes? Types, EquatableArray<DiagnosticInfo> Diagnostics)
    {
        public static KnownTypesResult Resolve(Compilation compilation)
        {
            var diagnostics = new List<DiagnosticInfo>();

            var formValues = ResolveInAssembly(compilation, FormValuesTypeName, diagnostics);
            var requestValues = ResolveInAssembly(compilation, RequestValuesTypeName, diagnostics);
            var validatableModel = ResolveInAssembly(compilation, ValidatableModelTypeName, diagnostics);

            // The executable validation attributes live in a referenced assembly, so they cannot be found by the
            // simple-name search over the compiled source. Each is resolved by metadata name in its own right: they
            // can be renamed or sub-namespaced one at a time, so anchoring on a single one would let a sibling's
            // move slip through as a dangling emitted reference.
            var allowedValues = ResolveExecutable(compilation, AllowedValuesAttributeName, diagnostics);
            var absoluteUri = ResolveExecutable(compilation, AbsoluteUriAttributeName, diagnostics);
            var elementsRequired = ResolveExecutable(compilation, ElementsRequiredAttributeName, diagnostics);

            if (formValues == null || requestValues == null || validatableModel == null ||
                allowedValues == null || absoluteUri == null || elementsRequired == null)
                return new KnownTypesResult(null, new EquatableArray<DiagnosticInfo>([.. diagnostics]));

            var known = new KnownTypes(
                formValues.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                requestValues.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                validatableModel.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                EmitName(allowedValues),
                EmitName(absoluteUri),
                EmitName(elementsRequired));

            return new KnownTypesResult(known, new EquatableArray<DiagnosticInfo>([]));
        }

        // An executable validation attribute is emitted by its short name (a C# attribute usage drops the
        // "Attribute" suffix), qualified with the type's own resolved namespace so a move follows the symbol.
        private static string EmitName(INamedTypeSymbol attribute)
        {
            const string suffix = "Attribute";
            var name = attribute.Name;
            var shortName = name.EndsWith(suffix, System.StringComparison.Ordinal)
                ? name.Substring(0, name.Length - suffix.Length)
                : name;
            return $"global::{attribute.ContainingNamespace.ToDisplayString()}.{shortName}";
        }

        private static INamedTypeSymbol? ResolveExecutable(
            Compilation compilation, string metadataName, List<DiagnosticInfo> diagnostics)
        {
            var symbol = compilation.GetTypeByMetadataName(metadataName);
            if (symbol == null)
                diagnostics.Add(new DiagnosticInfo(HelperTypeNotFound, LocationInfo.None, metadataName));

            return symbol;
        }

        private static INamedTypeSymbol? ResolveInAssembly(
            Compilation compilation, string simpleName, List<DiagnosticInfo> diagnostics)
        {
            var matches = compilation
                .GetSymbolsWithName(name => name == simpleName, SymbolFilter.Type)
                .OfType<INamedTypeSymbol>()
                .ToArray();

            switch (matches.Length)
            {
                case 1:
                    return matches[0];
                case 0:
                    diagnostics.Add(new DiagnosticInfo(HelperTypeNotFound, LocationInfo.None, simpleName));
                    return null;
                default:
                    diagnostics.Add(new DiagnosticInfo(HelperTypeAmbiguous, LocationInfo.None, simpleName));
                    return null;
            }
        }
    }

    /// <summary>
    /// Renders one Minimal API model from its core counterpart: the bound property declarations, the
    /// <c>BindAsync</c> reader and the implicit projection onto the core type.
    /// </summary>
    private sealed class ModelEmitter(StubInfo stub, INamedTypeSymbol coreType, KnownTypes known)
    {
        private readonly StringBuilder _writer = new();
        private readonly List<DiagnosticInfo> _diagnostics = [];

        // Per-property facts collected in one pass, then emitted as the property block, the BindAsync body and the
        // projection. Validations are the executable validation-attribute usages translated from the core markers.
        private readonly List<(string Name, string Type, string Initializer, List<string> Validations)> _properties = [];
        private readonly List<string> _preStatements = [];
        private readonly List<(string Name, string Expression)> _assignments = [];

        public GenerationResult Emit()
        {
            foreach (var property in CollectProperties(coreType))
            {
                var sourceMarker = TryGetSourceMarker(property);
                if (sourceMarker != null)
                    ClassifySource(property, sourceMarker);
                else if (!IsExcludedFromWire(property))
                    ClassifyWire(property);
                // A payload-excluded property without a transport-source marker is off-wire — it is not bound and
                // keeps its core default, so it is omitted from both the model and the projection.
            }

            _writer.AppendLine("// <auto-generated/>");
            _writer.AppendLine($"// Generated by Abblix.Oidc.Server.MinimalApi.SourceGeneration from {coreType.ToDisplayString()}.");
            _writer.AppendLine("#nullable enable");
            _writer.AppendLine();
            _writer.AppendLine($"namespace {stub.Namespace};");
            _writer.AppendLine();

            // When any property carries a translated validation attribute, the model opts into validation by the
            // group-scoped endpoint filter through this marker.
            var marker = _properties.Any(property => property.Validations.Count > 0) ? $" : {known.ValidatableModel}" : string.Empty;
            _writer.AppendLine($"public partial record {stub.Name}{marker}");
            _writer.AppendLine("{");

            EmitProperties();
            EmitBindAsync();
            EmitProjection();

            _writer.AppendLine("}");

            return new GenerationResult(
                $"{stub.Namespace}.{stub.Name}.g.cs",
                _writer.ToString(),
                new EquatableArray<DiagnosticInfo>([.. _diagnostics]));
        }

        private void ClassifySource(IPropertySymbol property, AttributeData sourceMarker)
        {
            var markerClass = sourceMarker.AttributeClass!;
            var type = property.Type.ToDisplayString(FullyQualifiedWithNullability);

            switch (markerClass.Name)
            {
                case RequestHeaderMarkerName
                    when sourceMarker.ConstructorArguments is [{ Value: string headerName }]:
                    _assignments.Add((property.Name, $"{known.FormValues}.Header(request, {Literal(headerName)})"));
                    break;

                case AuthorizationHeaderMarkerName:
                    // The Authorization header is the standard transport for client/registration credentials
                    // (RFC 9110 §11.6.2); parsed once into a local that every authorization-header property reads.
                    if (_preStatements.All(static statement => !statement.Contains("authorizationHeader")))
                    {
                        _preStatements.Add(
                            "global::System.Net.Http.Headers.AuthenticationHeaderValue? authorizationHeader = null;");
                        _preStatements.Add("var rawAuthorization = request.Headers.Authorization.ToString();");
                        _preStatements.Add(
                            "if (!string.IsNullOrEmpty(rawAuthorization)) " +
                            "global::System.Net.Http.Headers.AuthenticationHeaderValue.TryParse(rawAuthorization, out authorizationHeader);");
                    }

                    _assignments.Add((property.Name, "authorizationHeader"));
                    break;

                case ClientCertificateMarkerName:
                    // mTLS client certificate (RFC 8705): present only on a TLS connection that requested one.
                    if (_preStatements.All(static statement => !statement.Contains("clientCertificate")))
                    {
                        _preStatements.Add(
                            "var clientCertificate = context.Connection.ClientCertificate " +
                            "?? await context.Connection.GetClientCertificateAsync(context.RequestAborted);");
                    }

                    _assignments.Add((property.Name, "clientCertificate"));
                    break;

                default:
                    return;
            }

            _properties.Add((property.Name, type, GetInitializer(property), CollectValidations(property)));
        }

        private void ClassifyWire(IPropertySymbol property)
        {
            var wireName = GetWireName(property);
            if (wireName == null)
            {
                _diagnostics.Add(new DiagnosticInfo(
                    WireNameMissing, stub.Location, coreType.ToDisplayString(), property.Name));
                return;
            }

            var type = property.Type.ToDisplayString(FullyQualifiedWithNullability);
            _properties.Add((property.Name, type, GetInitializer(property), CollectValidations(property)));
            _assignments.Add((property.Name, GetBindExpression(property, wireName)));
        }

        /// <summary>
        /// Maps a wire-payload property to the expression that reads its value from <c>source</c> (which exposes a
        /// <c>this[string] -&gt; StringValues</c> indexer for both the form-only and query-or-form cases). The
        /// wire-format marker selects the value conversion; otherwise the property type does.
        /// </summary>
        private string GetBindExpression(IPropertySymbol property, string wireName)
        {
            var value = $"source[{Literal(wireName)}]";

            switch (GetWireFormatMarkerName(property))
            {
                case SpaceSeparatedStringMarkerName:
                    return IsNonNullableReference(property.Type)
                        ? $"{known.FormValues}.SpaceSeparated({value})"
                        : $"{known.FormValues}.SpaceSeparatedOrNull({value})";

                case TotalSecondsMarkerName:
                    return $"{known.FormValues}.Seconds({value})";

                case JsonObjectMarkerName:
                    var elementType = property.Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
                    return $"{known.FormValues}.Json<{elementType}>({value})";

                case CultureListMarkerName:
                    return $"{known.FormValues}.Cultures({value})";
            }

            if (property.Type is IArrayTypeSymbol array)
            {
                return array.ElementType.SpecialType == SpecialType.System_String
                    ? $"{known.FormValues}.Strings({value})"
                    : $"{known.FormValues}.ParseUris({value})";
            }

            if (property.Type.SpecialType == SpecialType.System_String)
            {
                return IsNonNullableReference(property.Type)
                    ? $"{value}.ToString()"
                    : $"{known.FormValues}.Value({value})";
            }

            if (property.Type.Name == "Uri")
                return $"{known.FormValues}.ParseUri({value})";

            if (IsNullableBoolean(property.Type))
                return $"{known.FormValues}.Bool({value})";

            return $"{known.FormValues}.Value({value})";
        }

        private void EmitProperties()
        {
            foreach (var (name, type, initializer, validations) in _properties)
            {
                _writer.AppendLine($"\t/// <inheritdoc cref=\"{coreType.ToDisplayString()}.{name}\"/>");
                foreach (var validation in validations)
                    _writer.AppendLine($"\t[{validation}]");
                _writer.AppendLine($"\tpublic {type} {name} {{ get; init; }}{initializer}");
                _writer.AppendLine();
            }
        }

        private void EmitBindAsync()
        {
            _writer.AppendLine("\t/// <summary>Binds the model from the request's form, query, headers and TLS connection.</summary>");
            _writer.AppendLine(
                $"\tpublic static async global::System.Threading.Tasks.ValueTask<{stub.Name}?> BindAsync(" +
                "global::Microsoft.AspNetCore.Http.HttpContext context)");
            _writer.AppendLine("\t{");
            _writer.AppendLine("\t\tvar request = context.Request;");

            foreach (var statement in _preStatements)
                _writer.AppendLine($"\t\t{statement}");

            // A form-only model never reads the query — per RFC 6749 the token-endpoint parameters must travel in the
            // request body. A SupportsGet model reads query-or-form via RequestValues.
            if (stub.SupportsGet)
            {
                _writer.AppendLine(
                    "\t\tvar form = request.HasFormContentType ? await request.ReadFormAsync(context.RequestAborted) : null;");
                _writer.AppendLine(
                    $"\t\tvar source = new {known.RequestValues}(request.Query, form);");
            }
            else
            {
                _writer.AppendLine(
                    "\t\tvar source = request.HasFormContentType " +
                    "? await request.ReadFormAsync(context.RequestAborted) " +
                    ": (global::Microsoft.AspNetCore.Http.IFormCollection)global::Microsoft.AspNetCore.Http.FormCollection.Empty;");
            }

            _writer.AppendLine($"\t\treturn new {stub.Name}");
            _writer.AppendLine("\t\t{");

            foreach (var (name, expression) in _assignments)
                _writer.AppendLine($"\t\t\t{name} = {expression},");

            _writer.AppendLine("\t\t};");
            _writer.AppendLine("\t}");
        }

        private void EmitProjection()
        {
            var coreTypeName = coreType.ToDisplayString(FullyQualifiedWithNullability);

            _writer.AppendLine();
            _writer.AppendLine("\t/// <summary>Projects the transport-bound model onto its core counterpart.</summary>");
            _writer.AppendLine($"\tpublic static implicit operator {coreTypeName}({stub.Name} request) => new()");
            _writer.AppendLine("\t{");

            foreach (var (name, _, _, _) in _properties)
                _writer.AppendLine($"\t\t{name} = request.{name},");

            _writer.AppendLine("\t};");
        }

        private static string? GetWireFormatMarkerName(IPropertySymbol property)
            => property.GetAttributes()
                .Select(static attribute => attribute.AttributeClass)
                .Where(static attributeClass =>
                    attributeClass?.ContainingNamespace.ToDisplayString() == DeclarativeValidationNamespace)
                .Select(static attributeClass => attributeClass!.Name)
                .FirstOrDefault(static name => name is
                    SpaceSeparatedStringMarkerName or TotalSecondsMarkerName or
                    JsonObjectMarkerName or CultureListMarkerName);

        /// <summary>
        /// Translates a core property's declarative validation markers into the executable Minimal API validation
        /// attribute usages emitted onto the generated property, so a <c>Validator</c> pass enforces them.
        /// </summary>
        private List<string> CollectValidations(IPropertySymbol property)
        {
            var validations = new List<string>();
            foreach (var attribute in property.GetAttributes())
            {
                var attributeClass = attribute.AttributeClass;
                if (attributeClass == null)
                    continue;

                var attributeNamespace = attributeClass.ContainingNamespace.ToDisplayString();
                if (attributeNamespace == DeclarativeValidationNamespace)
                {
                    switch (attributeClass.Name)
                    {
                        case AllowedValuesMarkerName:
                            validations.Add($"{known.AllowedValues}({ExtractStringArrayArgument(attribute)})");
                            break;

                        case AbsoluteUriMarkerName:
                            var scheme = attribute.ConstructorArguments is [{ Value: string requireScheme }]
                                ? $"({Literal(requireScheme)})"
                                : string.Empty;
                            validations.Add($"{known.AbsoluteUri}{scheme}");
                            break;

                        case ElementsRequiredMarkerName:
                            validations.Add($"{known.ElementsRequired}");
                            break;
                    }
                }
                else if (attributeNamespace == DataAnnotationsNamespace && attributeClass.Name == RequiredMarkerName)
                {
                    validations.Add($"global::{DataAnnotationsNamespace}.Required");
                }
            }

            return validations;
        }

        private static string ExtractStringArrayArgument(AttributeData attribute)
            => attribute.ConstructorArguments is [{ Kind: TypedConstantKind.Array, Values: var values }]
                ? string.Join(", ", values.Select(value => Literal((string)value.Value!)))
                : string.Empty;

        private static bool IsNonNullableReference(ITypeSymbol type)
            => type is { IsReferenceType: true, NullableAnnotation: NullableAnnotation.NotAnnotated };

        private static bool IsNullableBoolean(ITypeSymbol type)
            => type is INamedTypeSymbol
            {
                OriginalDefinition.SpecialType: SpecialType.System_Nullable_T,
                TypeArguments: [{ SpecialType: SpecialType.System_Boolean }]
            };

        private static string Literal(string value)
            => Microsoft.CodeAnalysis.CSharp.SymbolDisplay.FormatLiteral(value, quote: true);

        private static AttributeData? TryGetSourceMarker(IPropertySymbol property)
            => property.GetAttributes().FirstOrDefault(static attribute =>
                attribute.AttributeClass is
                {
                    Name: RequestHeaderMarkerName or AuthorizationHeaderMarkerName or ClientCertificateMarkerName,
                } attributeClass &&
                attributeClass.ContainingNamespace.ToDisplayString() == DeclarativeValidationNamespace);

        private static bool IsExcludedFromWire(IPropertySymbol property)
            => property.GetAttributes().Any(static attribute =>
                attribute.AttributeClass is { Name: JsonIgnoreAttributeName } attributeClass &&
                attributeClass.ContainingNamespace.ToDisplayString() == SystemTextJsonNamespace);

        private static string? GetWireName(IPropertySymbol property)
            => property.GetAttributes()
                .Where(static attribute =>
                    attribute.AttributeClass is { Name: JsonPropertyNameAttributeName } attributeClass &&
                    attributeClass.ContainingNamespace.ToDisplayString() == SystemTextJsonNamespace)
                .Select(static attribute =>
                    attribute.ConstructorArguments is [{ Value: string wireName }] ? wireName : null)
                .FirstOrDefault(static wireName => wireName != null);

        private static string GetInitializer(IPropertySymbol property)
        {
            if (property.Type is { IsReferenceType: true, NullableAnnotation: NullableAnnotation.NotAnnotated })
                return property.Type.TypeKind == TypeKind.Array ? " = [];" : " = null!;";

            return string.Empty;
        }

        private static IEnumerable<IPropertySymbol> CollectProperties(INamedTypeSymbol type)
        {
            var seen = new HashSet<string>();

            for (var current = type; current != null && current.SpecialType != SpecialType.System_Object;
                 current = current.BaseType)
            {
                var declared = current.GetMembers()
                    .OfType<IPropertySymbol>()
                    .Where(static property =>
                        property is { IsStatic: false, IsImplicitlyDeclared: false, DeclaredAccessibility: Accessibility.Public } &&
                        !HasCompilerGeneratedAttribute(property))
                    .Where(property => seen.Add(property.Name));

                foreach (var property in declared)
                    yield return property;
            }
        }

        private static bool HasCompilerGeneratedAttribute(ISymbol symbol)
            => symbol.GetAttributes().Any(static attribute =>
                attribute.AttributeClass is { Name: nameof(System.Runtime.CompilerServices.CompilerGeneratedAttribute) } attributeClass &&
                attributeClass.ContainingNamespace.ToDisplayString() == CompilerServicesNamespace);
    }
}
