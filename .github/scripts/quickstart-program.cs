#:package Microsoft.CodeAnalysis.CSharp@5.12.0

// Writes the Program.cs a reader of a README quickstart ends up with: the README block, taken from its compiled
// copy under tests/Abblix.DocSamples/Samples (ReadmeSampleTests holds each copy to its README's lines), plus the
// two lines the repository README's outline paragraph says the host adds and a protocol request needs: a
// distributed cache and the CORS middleware. The release workflow builds the result in a project made by
// `dotnet new web`.
//
//   dotnet quickstart-program.cs <path to the compiled copy> <path of the Program.cs to write>
//
// The block is read as C# syntax, never as text: the statements of the copy's Configure method become the
// top-level statements, and the host's lines go after the statements that create the builder and build the app.
// Run it from outside this repository: inside, the repository's central package versions refuse the version
// named above.

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using static Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

if (args is not [var samplePath, var programPath])
{
    Console.Error.WriteLine("Usage: dotnet quickstart-program.cs <compiled copy of the block> <Program.cs to write>");
    return 2;
}

var tree = CSharpSyntaxTree.ParseText(File.ReadAllText(samplePath), path: samplePath);
var errors = tree.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error).ToList();
if (errors.Count > 0)
{
    foreach (var error in errors)
        Console.Error.WriteLine(error);
    return 1;
}

var unit = tree.GetCompilationUnitRoot();
var configure = unit.DescendantNodes()
    .OfType<MethodDeclarationSyntax>()
    .Where(method => method is { Identifier.Text: "Configure", Body: not null })
    .ToList();
if (configure is not [{ Body: { } body }])
    return Fail($"{samplePath} declares {configure.Count} Configure methods with a body, where the copy of a quickstart has one");

var statements = body.Statements.ToList();

// After the builder exists: services are registered before Build
var (builderAt, builder) = Declaration(statements, "CreateBuilder");
if (builderAt < 0)
    return Fail("The quickstart declares no variable initialized by WebApplication.CreateBuilder(...)");

// After the app is built and before the endpoints are mapped: the CORS middleware runs after routing, which
// WebApplication places at the start of the pipeline, so it has to be in the app's own pipeline, not around it
var (appAt, app) = Declaration(statements, "Build");
if (appAt < 0)
    return Fail("The quickstart declares no variable initialized by <builder>.Build()");

statements.Insert(appAt + 1, HostLine($"{app}.UseCors();"));
statements.Insert(builderAt + 1, HostLine($"{builder}.Services.AddDistributedMemoryCache();"));

// Each node keeps its own comments and line breaks, so the file reads like the README block it came from
var program = string.Concat(unit.Usings.Select(directive => directive.WithoutLeadingTrivia().ToFullString()))
              + string.Concat(statements.Select(statement => statement.ToFullString()));

File.WriteAllText(programPath, program);
Console.WriteLine($"Wrote {programPath}:");
Console.WriteLine(program);
return 0;

// The index and name of the single variable whose initializer calls a method of that name, or -1 when none does
static (int Index, string Name) Declaration(List<StatementSyntax> statements, string method)
{
    for (var index = 0; index < statements.Count; index++)
    {
        if (statements[index] is LocalDeclarationStatementSyntax
            {
                Declaration.Variables: [
                {
                    Initializer.Value: InvocationExpressionSyntax
                    {
                        Expression: MemberAccessExpressionSyntax { Name.Identifier.Text: var name },
                    },
                } variable],
            } && name == method)
        {
            return (index, variable.Identifier.Text);
        }
    }

    return (-1, string.Empty);
}

static StatementSyntax HostLine(string code)
    => ParseStatement(code)
        .WithLeadingTrivia(LineFeed, Comment("// Added by the host, as the README's outline asks"), LineFeed)
        .WithTrailingTrivia(LineFeed);

static int Fail(string message)
{
    Console.Error.WriteLine(message);
    return 1;
}
