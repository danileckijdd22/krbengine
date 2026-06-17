using System;
using System.Collections.Generic;

namespace krbengine
{
    public class DelegationEngine
    {
        // Запуск LDAP-аудита настроек делегирования в Active Directory
        public static void Run(Dictionary<string, string> opt)
        {
            string dcIp = opt["-dc-ip"];
            string domain = opt["-d"];
            string creds = opt["-u"];

            string identity = creds.Contains(":") ? creds.Split(':')[0] : creds;

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[*] ЗАПУСК МОДУЛЯ: DELEGATION");
            Console.WriteLine($"    DC: {dcIp} | Domain: {domain} | Identity: {identity}");
            Console.ResetColor();

            string filter = "(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=1048576)(msDS-AllowedToDelegateTo=*))";
            string[] attributes = { "sAMAccountName", "userAccountControl", "msDS-AllowedToDelegateTo", "distinguishedName", "objectClass" };

            try
            {
                var searchResults = LdapClient.Search(dcIp, domain, creds, filter, attributes);

                if (searchResults.Count == 0)
                {
                    Console.WriteLine("[-] Уязвимые настройки не найдены.");
                    return;
                }

                Console.WriteLine($"[+] Объектов для анализа: {searchResults.Count}\n");

                foreach (var entry in searchResults)
                {
                    string sam = entry.ContainsKey("sAMAccountName") ? entry["sAMAccountName"][0] : "Unknown";
                    string dn = entry.ContainsKey("distinguishedName") ? entry["distinguishedName"][0] : "Unknown";
                    string type = entry.ContainsKey("objectClass") ? entry["objectClass"][entry["objectClass"].Count - 1] : "Unknown";

                    int uac = 0;
                    if (entry.ContainsKey("userAccountControl")) int.TryParse(entry["userAccountControl"][0], out uac);

                    // Анализ флагов
                    bool isUnconstrained = (uac & 524288) == 524288;
                    bool isSensitive = (uac & 1048576) == 1048576;
                    bool isConstrained = entry.ContainsKey("msDS-AllowedToDelegateTo");
                    bool isProtocolTransition = (uac & 16777216) == 16777216;

                    // Вывод общей инфы об объекте
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine($"[Object: {sam}]");
                    Console.ResetColor();
                    Console.WriteLine($"  Path: {dn}");
                    Console.WriteLine($"  Type: {type}");

                    if (isSensitive)
                    {
                        Console.ForegroundColor = ConsoleColor.Blue;
                        Console.WriteLine("  [i] Защищено: Аккаунт помечен как Sensitive (Делегирование запрещено).");
                        Console.ResetColor();
                    }

                    if (isUnconstrained)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("  [!] Unconstrained Delegation: ВЫСОКИЙ РИСК");
                        Console.WriteLine("      Любой TGT, отправленный этому сервису, может быть перехвачен.");
                        Console.ResetColor();
                    }

                    if (isConstrained)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        string mode = isProtocolTransition ? "С переходом протокола (S4U2Self)" : "Только Kerberos";
                        Console.WriteLine($"  [*] Constrained Delegation: {mode}");
                        Console.WriteLine("      Разрешен проброс прав к сервисам:");
                        foreach (var spn in entry["msDS-AllowedToDelegateTo"])
                        {
                            Console.WriteLine($"        -> {spn}");
                        }
                        Console.ResetColor();
                    }
                    Console.WriteLine(new string('-', 60));
                }
                Console.WriteLine("\n[*] Модуль Delegation завершил работу.");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[!] Ошибка LDAP: {ex.Message}");
                Console.ResetColor();
            }
        }
    }
}