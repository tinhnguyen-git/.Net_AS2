using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Net.AS2.Data;
using Net.AS2.Data.Entity.Context;
using Net.AS2.Data.Services;
using Net.AS2.Core.Helper;
using Net.AS2.Receiver.Middleware;
using Net.AS2.Core.Settings;
using System.Text;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
var fileLocation = builder.Configuration.GetSection("FileLocation").Get<FileLocation>();
builder.Services.AddSingleton(fileLocation);
var adminInfo = builder.Configuration.GetSection("AdminInfo").Get<AdminInfo>();
builder.Services.AddSingleton(adminInfo);
builder.Services.AddScoped<IAS2DatabaseContext, AS2MongoDBContext>();
builder.Services.AddScoped(typeof(IAS2Repository<>), typeof(AS2MongoRepository<>));
builder.Services.AddScoped<ILogFileWriter, LogFileWriter>();
builder.Services.AddScoped<IAS2ConnectionService, AS2ConnectionService>();
Log.Logger = new LoggerConfiguration().ReadFrom.Configuration(builder.Configuration).CreateLogger();
builder.Host.UseSerilog(Log.Logger);
//// If using Kestrel:
//builder.Services.Configure<KestrelServerOptions>(options =>
//{
//    options.AllowSynchronousIO = true;
//});

//// If using IIS:
//builder.Services.Configure<IISServerOptions>(options =>
//{
//    options.AllowSynchronousIO = true;
//});
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

//app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseSerilogRequestLogging();
app.UseRouting();

app.UseAuthorization();

app.UseForwardedHeaders(new ForwardedHeadersOptions {
    ForwardedHeaders = ForwardedHeaders.XForwardedFor |
    ForwardedHeaders.XForwardedProto
});
app.UseStatusCodePages((StatusCodeContext statusCodeContext) =>
{
    var context = statusCodeContext.HttpContext;
    if (context.Response.StatusCode == 404)
    {
        context.Response.StatusCode = 200;
        context.Response.ContentType = "text/html";
        var message = @"<!DOCTYPE HTML PUBLIC ""-//W3C//DTD HTML 3.2 Final//EN"">"
            + @"<HTML><HEAD><TITLE>Generic AS2 Receiver</TITLE></HEAD>"
            + @"<BODY><H1>200</H1></BODY></HTML>";
        byte[] bytes = Encoding.ASCII.GetBytes(message);
        return context.Response.Body.WriteAsync(bytes).AsTask();
    }

    return Task.CompletedTask;
});
app.UseMiddleware<TenantRoutingMiddleware>();

app.MapWhen(context => context.Request.Path.ToString().EndsWith("HttpReceiver"),
         appBuilder => {
             appBuilder.UseDataReceiverMiddleware();
         });
app.MapWhen(context => context.Request.Path.ToString().EndsWith("HttpMdn"),
         appBuilder => {
             appBuilder.UseMdnReceiverMiddleware();
         });
app.MapWhen(context => context.Request.Path.ToString().EndsWith("TestSend"),
         appBuilder => {
             appBuilder.UseTestSendMiddleware();
         });
app.UseEndpoints(e => { });
app.Run();
