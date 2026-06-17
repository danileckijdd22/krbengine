# krbengine

`krbengine` — консольный инструмент для проведения тестовых атак и аудита конфигураций Kerberos/Active Directory в контролируемой лабораторной среде.

Проект разработан в рамках дипломной работы на тему:
«Создание инструмента для проведения тестовых атак на инфраструктуру протокола Kerberos»

## Автор

Данилецкий Даниил Дмитриевич
Группа: СДП-КБ-221

## Назначение проекта

Инструмент предназначен для демонстрации и проверки отдельных сценариев атак на инфраструктуру Kerberos в доменной среде Active Directory. Реализация ориентирована на исследование сетевого обмена, структуры Kerberos-сообщений, PAC-блоков и ошибок конфигурации домена.

Проект предназначен только для учебного и лабораторного использования в средах, где проведение тестирования разрешено.

## Возможности

* Kerberoasting — поиск SPN-учетных записей и извлечение сервисных билетов.
* AS-REProasting — проверка пользователей с отключенной предварительной Kerberos-аутентификацией.
* Delegation Audit — аудит параметров делегирования в Active Directory.
* TicketForge — локальное формирование Silver Ticket с построением PAC и сервисного билета.

## Структура проекта

```text
krbengine/
├── Engines/
│   ├── AsRepRoastEngine.cs
│   ├── DelegationEngine.cs
│   ├── KerberoastEngine.cs
│   └── TicketForgeEngine.cs
├── CustomCryptoPal.cs
├── LdapClient.cs
├── NetworkClient.cs
├── Program.cs
├── krbengine.csproj
├── .gitignore
└── README.md
```

## Требования

Для сборки и запуска проекта требуется:

* .NET SDK 8.0 или новее;
* Windows 10/11 или Linux x64;
* лабораторная среда Active Directory;
* разрешение на проведение тестирования;
* сетевой доступ к контроллеру домена.

## Сборка

Восстановление зависимостей:

```bash
dotnet restore
```

Сборка проекта:

```bash
dotnet build -c Release
```

## Создание исполняемых файлов

Публикация self-contained версии для Windows x64:

```bash
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
```

Публикация self-contained версии для Linux x64:

```bash
dotnet publish -c Release -r linux-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
```

После публикации исполняемые файлы будут находиться в каталогах:

```text
bin/Release/net8.0/win-x64/publish/
bin/Release/net8.0/linux-x64/publish/
```

## Использование

Общий формат запуска:

```bash
krbengine.exe <module> [parameters]
```

Вывод общей справки:

```bash
krbengine.exe -h
```

Справка по конкретному модулю:

```bash
krbengine.exe kerberoast -h
krbengine.exe asreproast -h
krbengine.exe delegation -h
krbengine.exe forge -h
```

## Модули

### Kerberoast

Модуль выполняет LDAP-поиск учетных записей с SPN, после чего запрашивает сервисные билеты TGS и формирует строки для последующего оффлайн-аудита паролей.

Пример:

```bash
krbengine.exe kerberoast -dc-ip <dc_ip> -d <domain> -u <user:password>
```

### AS-REProast

Модуль проверяет учетные записи, для которых отключена предварительная Kerberos-аутентификация, и при наличии такой конфигурации извлекает AS-REP hash.

Пример LDAP-разведки:

```bash
krbengine.exe asreproast -dc-ip <dc_ip> -d <domain> -u <user:password>
```

Пример точечной проверки пользователя:

```bash
krbengine.exe asreproast -dc-ip <dc_ip> -d <domain> -tu <target_user>
```

### Delegation Audit

Модуль выполняет LDAP-аудит параметров делегирования в Active Directory и выводит объекты с потенциально опасными настройками.

Пример:

```bash
krbengine.exe delegation -dc-ip <dc_ip> -d <domain> -u <user:password>
```

### TicketForge

Модуль локально формирует Silver Ticket для выбранного сервисного SPN. В процессе создается PAC, выполняется расчет подписей и формируется `.kirbi`-файл для последующего внедрения в Kerberos-кэш.

Пример:

```bash
krbengine.exe forge -d <domain> -u <user> -sid <domain_sid> -rid <rid> -hash <service_key> -spn <service_spn> -kvno <kvno> -groups <group_rids> -out <ticket.kirbi>
```

Пример для CIFS-сервиса:

```bash
krbengine.exe forge -d CORP.LOCAL -u Administrator -sid S-1-5-21-... -rid 500 -hash <key> -spn cifs/server.corp.local -kvno 4 -groups 513,512,519 -out admin.kirbi
```

## Ограничения

Инструмент не предназначен для использования в сторонних инфраструктурах без разрешения владельца. Все проверки должны выполняться только в лабораторной среде или в рамках согласованного аудита.