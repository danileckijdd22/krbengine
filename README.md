# krbengine

## 📌 Данные об авторе

Данилецкий Д. Д.  
Группа: СДП-КБ-221  
Специальность: «Компьютерная безопасность»  

## 📋 Описание проекта

`krbengine` — консольный инструмент для проведения тестовых атак на инфраструктуру протокола Kerberos в среде Active Directory.

Проект разработан в рамках дипломной работы на тему: «Создание инструмента для проведения тестовых атак на инфраструктуру протокола Kerberos». Инструмент используется для проверки отдельных сценариев взаимодействия с Kerberos и LDAP, включая получение сервисных билетов, проверку учетных записей без предварительной аутентификации, аудит настроек делегирования и локальное формирование Silver Ticket.

## ⚙️ Возможности

- `kerberoast` — поиск SPN-учетных записей и извлечение сервисных TGS-билетов.
- `asreproast` — проверка учетных записей с отключенной предварительной Kerberos-аутентификацией.
- `delegation` — аудит параметров делегирования в Active Directory.
- `forge` — локальное формирование Silver Ticket с построением PAC и сервисного билета.

## 📁 Структура проекта

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

## 🛠 Требования

Для сборки проекта требуется:

- .NET SDK 8.0 или новее;
- Git для клонирования репозитория;
- Windows или Linux.

При публикации в self-contained режиме исполняемый файл запускается без отдельной установки .NET Runtime.

## 🚀 Сборка и создание исполняемых файлов

Клонирование репозитория:

```bash
git clone https://github.com/danileckijdd22/krbengine.git
cd krbengine
```

Восстановление зависимостей:

```bash
dotnet restore
```

Сборка проекта:

```bash
dotnet build -c Release
```

Создание исполняемого файла для Windows x64:

```bash
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
```

Создание исполняемого файла для Linux x64:

```bash
dotnet publish -c Release -r linux-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
```

После публикации исполняемые файлы будут находиться в каталогах:

```text
bin/Release/net8.0/win-x64/publish/
bin/Release/net8.0/linux-x64/publish/
```

## ▶️ Использование

Общий формат запуска для Windows:

```bash
krbengine.exe <модуль> [параметры]
```

Общий формат запуска для Linux:

```bash
./krbengine <модуль> [параметры]
```

Вывод справки:

```bash
krbengine -h
```

Справка по конкретному модулю вызывается через параметр `-h` после названия модуля:

```bash
krbengine <модуль> -h
```

## ⚠️ Ограничение

Инструмент предназначен для учебного использования, лабораторного тестирования и согласованного аудита. Применение допускается только в рамках действующего законодательства и при наличии разрешения владельца инфраструктуры. Ответственность за использование инструмента и возможные последствия его применения несет пользователь.