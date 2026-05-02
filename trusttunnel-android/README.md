# TrustTunnel Android Client

Полноценный Android клиент TrustTunnel VPN с интерфейсом, идентичным Qt десктопному приложению.

## Особенности

- **Идентичный дизайн Qt приложению** с брендом Claude (фиолетовый, оранжевый)
- **QR код импорт конфигов** из Qt приложения
- **Сканирование QR кодов** встроенной камерой (ML Kit)
- **Управление конфигурациями** с сохранением
- **Уведомления** о состоянии подключения
- **Настройки** (Kill Switch, Notifications, Log Level)
- **Статистика трафика** (в разработке)

## Требования

- Android SDK 26+ (минимум Android 8.0)
- Android NDK 28.1.13356709+
- Java 11+
- Gradle 8.5+

## Сборка

### Из командной строки

```bash
cd trusttunnel-android

# Debug версия
./gradlew assembleDebug

# Release версия
./gradlew assembleRelease
```

APK будет находиться в `app/build/outputs/apk/`

### Из Android Studio

1. Откройте `trusttunnel-android/` как проект в Android Studio
2. Дождитесь синхронизации Gradle
3. Нажмите Run → Run 'app' или Build → Build Bundle(s) / APK(s)

## Структура проекта

```
trusttunnel-android/
├── app/
│   ├── src/main/
│   │   ├── kotlin/
│   │   │   └── com/trusttunnel/android/
│   │   │       ├── MainActivity.kt
│   │   │       ├── QRScannerActivity.kt
│   │   │       ├── SettingsActivity.kt
│   │   │       ├── VpnService.kt
│   │   │       └── data/
│   │   │           └── ConfigManager.kt
│   │   └── res/
│   │       ├── layout/
│   │       ├── values/
│   │       └── drawable/
│   └── build.gradle.kts
├── gradle/wrapper/
├── build.gradle.kts
├── settings.gradle.kts
└── README.md
```

## Использование

### Импорт конфигурации

1. На Qt клиенте, нажмите кнопку QR для конфигурации
2. На Android, нажмите "Scan QR"
3. Отсканируйте QR код
4. Конфигурация будет импортирована автоматически

### Подключение к VPN

1. Выберите конфигурацию из выпадающего списка
2. Нажмите "Connect"
3. При первом подключении разрешите использование VPN
4. Статус изменится на "CONNECTED"

## Цветовая схема (Claude Brand)

- **Фиолетовый** (#9D7EB8) - основной цвет
- **Фиолетовый темный** (#6B5B73) - заголовки
- **Оранжевый** (#FF9500) - акцент (QR кнопка)
- **Зеленый** (#10B981) - статус подключения
- **Красный** (#EF4444) - статус ошибки

## Расширение функциональности

### Добавление поддержки trusttunnel-core

Чтобы интегрировать нативный trusttunnel-core:

1. Свяжите library из `platform/android/lib/`
2. Реализуйте JNI обертки в `VpnService.kt`
3. Скомпилируйте trusttunnel-core для Android NDK

```kotlin
// build.gradle.kts
dependencies {
    implementation project(':lib')  // trusttunnel android library
}
```

## Лицензия

MIT License - см. LICENSE в корне проекта
