using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Net;

namespace krbengine
{
    public class LdapClient
    {
        // Выполнение LDAP-поиска с заданным фильтром и набором возвращаемых атрибутов
        public static List<Dictionary<string, List<string>>> Search(
            string dcIp, 
            string domain, 
            string credentials, 
            string filter, 
            string[] attributesToLoad)
        {
            var results = new List<Dictionary<string, List<string>>>();
            
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(dcIp, 389);
            
            using (LdapConnection connection = new LdapConnection(identifier))
            {
                connection.SessionOptions.ProtocolVersion = 3;
                connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                
                string user = "";
                string password = "";

                if (!string.IsNullOrEmpty(credentials))
                {
                    if (credentials.Equals("anonymous", StringComparison.OrdinalIgnoreCase))
                    {
                        connection.AuthType = AuthType.Anonymous;
                        connection.Bind();
                    }
                    else if (credentials.Contains(":"))
                    {
                        connection.AuthType = AuthType.Basic;
                        var parts = credentials.Split(new[] { ':' }, 2);
                        user = parts[0];
                        password = parts[1];
                        
                        string upn = user.Contains("@") ? user : $"{user}@{domain}";
                        connection.Bind(new NetworkCredential(upn, password));
                    }
                    else
                    {
                        throw new ArgumentException("Неверный формат учетных данных. Используйте 'user:password' или 'anonymous'.");
                    }
                }

                string searchBase = "DC=" + string.Join(",DC=", domain.Split('.'));
                SearchRequest request = new SearchRequest(
                    searchBase, 
                    filter, 
                    SearchScope.Subtree, 
                    attributesToLoad
                );

                SearchResponse response = (SearchResponse)connection.SendRequest(request);
                if (response != null && response.Entries != null)
                {
                    foreach (SearchResultEntry entry in response.Entries)
                    {
                        var entryDict = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

                        foreach (string attrName in attributesToLoad)
                        {
                            if (entry.Attributes.Contains(attrName))
                            {
                                var values = new List<string>();
                                DirectoryAttribute attr = entry.Attributes[attrName];
                                object[] rawValues = attr.GetValues(typeof(string));
                                foreach (var val in rawValues)
                                {
                                    values.Add(val.ToString());
                                }
                                entryDict[attrName] = values;
                            }
                        }
                        results.Add(entryDict);
                    }
                }
            }
            
            return results;
        }
    }
}