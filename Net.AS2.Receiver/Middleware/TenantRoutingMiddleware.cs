using Net.AS2.Data;
using Net.AS2.Data.Entity.Context;
using Net.AS2.Data.Services;
using System.Text.RegularExpressions;

namespace Net.AS2.Receiver.Middleware
{
    public class TenantRoutingMiddleware
    {
        private readonly RequestDelegate _next;

        public TenantRoutingMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context, AdminInfo adminInfo)
        {
            var requestAccessAssetFile = new Regex("\\.(\\w{2,5})(?:$|\\?)"); //js, css, jpg, png, svg, gif, woff, woff2,...
            if (context == null || context.Request == null || requestAccessAssetFile.IsMatch(context.Request.Path))
            {
                await _next(context);
                return;
            }

            var requestHost = context.Request.Host.Value;
            var dbContext = context.RequestServices.GetRequiredService<IAS2DatabaseContext>();
            dbContext.SetConnection(adminInfo.MainConnectionString);
            // Do not check if access admin url
            if (requestHost != adminInfo.AdminUrl)
            {
                if (requestHost.Contains("localhost:5021"))
                    requestHost = "teststore.localhost:16593";
                var tenantService = context.RequestServices.GetRequiredService<IAS2ConnectionService>();
                var tenant = tenantService.GetTenantByUrlOrDomain(requestHost);
                if (tenant != null)
                {
                    dbContext.SetConnection(tenant.MongoConnectionString);
                    var tenantRepository = context.RequestServices.GetRequiredService<IAS2Repository<Net.AS2.Data.Entity.Tenant>>();
                    tenantRepository.SetConnectionString(tenant.MongoConnectionString);
                    var ediConfigurationRepository = context.RequestServices.GetRequiredService<IAS2Repository<Net.AS2.Data.Entity.EdiConfiguration>>();
                    ediConfigurationRepository.SetConnectionString(tenant.MongoConnectionString);
                    var ediConnectivityRepository = context.RequestServices.GetRequiredService<IAS2Repository<Net.AS2.Data.Entity.EdiConnectivity>>();
                    ediConnectivityRepository.SetConnectionString(tenant.MongoConnectionString);
                    var dataResponseQueueRepository = context.RequestServices.GetRequiredService<IAS2Repository<Net.AS2.Data.Entity.DataResponseQueue>>();
                    dataResponseQueueRepository.SetConnectionString(tenant.MongoConnectionString);
                }
            }
            await _next(context);
        }
    }
}
