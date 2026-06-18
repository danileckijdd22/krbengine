# krbengine

Консольный инструмент для проведения тестовых атак на инфраструктуру протокола Kerberos в среде Active Directory.
Проект разработан в рамках дипломной работы на тему: «Создание инструмента для проведения тестовых атак на инфраструктуру протокола Kerberos». Инструмент используется для проверки отдельных сценариев взаимодействия с Kerberos и LDAP, включая получение сервисных билетов, проверку учетных записей без предварительной аутентификации, аудит настроек делегирования и локальное формирование Silver Ticket.

## 📌 Данные об авторе

Данилецкий Д. Д.  
Группа: СДП-КБ-221  
Специальность: «Компьютерная безопасность»  

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
- ОС: Windows или Linux.

При публикации в self-contained режиме исполняемый файл запускается без отдельной установки .NET Runtime.

## 🚀 Сборка и создание исполняемых файлов

Шаг 1: Клонируйте репозиторий

```bash
git clone https://github.com/danileckijdd22/krbengine.git
cd krbengine
```

Шаг 2: Восстановите зависимости

```bash
dotnet restore
```

Шаг 3: Соберите проект

```bash
dotnet build -c Release
```

Шаг 4: Создайте исполняемый файл

```bash
# Создание исполняемого файла для Windows x64:
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true -o publish/win-x64

# Создание исполняемого файла для Linux x64:
dotnet publish -c Release -r linux-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true -o publish/linux-x64
```

После выполнения в текущем каталоге проекта появится папка `publish` с вашим исполняемым файлом:

```text
publish/
├── win-x64/
│   └── krbengine.exe
└── linux-x64/
    └── krbengine
```

## 💻 Использование

Общий формат запуска:

```bash
# Windows
krbengine.exe <модуль> [параметры]

# Linux
./krbengine <модуль> [параметры]
```

Для получения справки о имеющихся модуля или параметрах конкретного, используйте параметр `-h` или `-help`

```bash
# Информация о модулях:
krbengine -h

```
```bash
# Информация о параметрах конретного модуля:
krbengine <модуль> -h
```

## ⚠️ Ограничение

Инструмент предназначен для учебного использования, лабораторного тестирования и согласованного аудита. Применение допускается только в рамках действующего законодательства и при наличии разрешения владельца инфраструктуры. Ответственность за использование инструмента и возможные последствия его применения несет пользователь.