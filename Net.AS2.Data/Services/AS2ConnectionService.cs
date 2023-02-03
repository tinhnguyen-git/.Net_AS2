using Net.AS2.Data.Entity;
using Net.AS2.Data.Entity.Context;
using Serilog.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Net.AS2.Data.Services
{
    public interface IAS2ConnectionService
    {
        EdiConnectivity? GetConnectivityByActivityId(string activityId, string as2Id);
        Tenant? GetTenantByAs2Id(string as2Id);
        Tenant? GetTenantByUrlOrDomain(string url);
        Task<bool> SaveMdnMessage(string activityId, string as2Id, string mdnMessage);
        EdiConfiguration? GetEdiConfigurationByAs2Id(string as2Id);
    }
    public class AS2ConnectionService : IAS2ConnectionService
    {
        private readonly IAS2Repository<EdiConfiguration> _ediConfigurationRepository;
        private readonly IAS2Repository<EdiConnectivity> _ediConnectivityRepository;
        private readonly IAS2Repository<Tenant> _tenantRepository;
        public AS2ConnectionService(IAS2Repository<EdiConfiguration> ediConfigurationRepository,
            IAS2Repository<EdiConnectivity> ediConnectivityRepository,
            IAS2Repository<Tenant> tenantRepository)
        {
            _ediConfigurationRepository = ediConfigurationRepository;
            _ediConnectivityRepository = ediConnectivityRepository;
            _tenantRepository = tenantRepository;
        }
        public async Task<bool> SaveMdnMessage(string activityId, string as2Id, string mdnMessage)
        {
            try
            {
                var connectivity = GetConnectivityByActivityId(activityId, as2Id);
                //TODO need update this code to store MDN to Interchange table, waiting Hiển finish that table
                if (connectivity != null)
                {
                    connectivity.MdnMessage = mdnMessage;
                    await _ediConnectivityRepository.UpdateAsync(connectivity);
                    return true;
                }                
            }
            catch (Exception ex)
            {
                Serilog.Log.Logger.Error(ex, "AS2ConnectionService.SaveMdnMessage");
            }
            return false;
        }
        public EdiConfiguration? GetEdiConfigurationByAs2Id(string as2Id)
        {
            try
            {
                var ediConfig = _ediConfigurationRepository.Table.Where(s => s.ToAs2.As2Id == as2Id).FirstOrDefault();
                return ediConfig;
            }
            catch (Exception ex)
            {
                Serilog.Log.Logger.Error(ex, "AS2ConnectionService.GetEdiConfigurationByAs2Id");
            }
            return null;
        }
        public EdiConnectivity? GetConnectivityByActivityId(string activityId, string as2Id)
        {
            try
            {
                //var ediConnectivity = (from con in _ediConnectivityRepository.Table
                //join config in _ediConfigurationRepository.Table on con.EdiConfigurationId equals config.Id
                //where con.Id == activityId
                //&& config.ToAs2.As2Id == as2Id
                //select con).FirstOrDefault();
                //return ediConnectivity;
                var ediConfig = _ediConfigurationRepository.Table.Where(s => s.ToAs2.As2Id == as2Id).FirstOrDefault();
                if (ediConfig != null)
                {
                    var ediConnectivity = _ediConnectivityRepository.Table.AsQueryable().Where(con => con.Id == activityId &&
                    con.EdiConfigurationId == ediConfig.Id).FirstOrDefault();
                    return ediConnectivity;
                }
            }
            catch (Exception ex)
            {
                Serilog.Log.Logger.Error(ex, "AS2ConnectionService.GetConnectivityByActivityId");
            }
            return null;
        }
        public Tenant? GetTenantByAs2Id(string as2Id)
        {
            var tenant = (from con in _tenantRepository.Table
                          where con.AS2Profile.As2Id == as2Id
                          select con).FirstOrDefault();
            return tenant;
        }
        public Tenant? GetTenantByUrlOrDomain(string url)
        {
            var result = _tenantRepository.Table.SingleOrDefault(tenant => tenant.Url.ToLower() == url.ToLower() ||
                        tenant.StoreDomains.Any(s => s.HostName.ToLower() == url.ToLower()));
            return result;
        }
    }
}
